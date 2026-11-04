#!/usr/bin/env python3
BOT_VERSION = "2.0.4"
"""Generic giveaway bot — first-come, one account per Telegram user.

The prize is NOT hardcoded: the item name, channel and accounts all live
in config files the manager app edits over SSH, so the same bot can give
away CapCut accounts today and any other accounts tomorrow.


Rules (fail-closed, no credentials in logs):
  * Claim key is the Telegram user ID (numeric, never changes), NOT username.
  * A user who already claimed gets THE SAME account again on repeat
    (useful if they lost the DM), never a second account.
  * Channel membership is checked on every claim via getChatMember.
    Statuses creator / administrator / member / restricted count as joined;
    left / kicked / error count as NOT joined. The bot must be an admin
    of the channel, otherwise getChatMember fails and claims are blocked.
  * Claims are assigned inside a single SQLite IMMEDIATE transaction, so
    two simultaneous clicks can never receive the same account.
  * Credentials are sent ONLY by private DM to the claimer, never to the
    channel, a group, or the log. The state DB stores only user_id and
    account_index — never login/password.

v2.0.4 change:
  * Ever-claimed blocklist: a user who received an account in ANY
    earlier giveaway can never receive one again. A new ever_claimed
    table records every claimer forever; the app Reset clears only
    the current giveaway's claims (plus the stored post id), so
    ever_claimed survives every Reset by construction. Claim order:
    current-claim repeat first (same account resent), then
    ever-claimed block (short message, no account consumed, post
    count unchanged), then a new claim, which inserts into BOTH
    claims and ever_claimed in one transaction.
  * Grandfather migration (one-time, idempotent, on startup): if
    ever_claimed is empty, current claims rows are copied into it,
    so people who already took accounts before this update are
    remembered. It never re-copies afterwards. Limitation: claims
    already cleared by a Reset before this update are gone and
    cannot be grandfathered — only claims present at upgrade time
    are remembered.

v2.0.3 change:
  * Bulk import (app-side): accounts.json may now hold code-only
    entries (username set, password empty) as well as
    username|password and username|password|2fa entries. The app
    parses one account per pasted line; this bot only reads the
    resulting accounts.json, so the two sides agree on that file.
  * Channel normalisation: a pasted full link (https://t.me/<name>)
    is now reduced to the plain channel name, so the earlier
    "chat not found" failure from a link in config.json cannot recur.
  * Claim DM is intro + credentials ONLY, no footer lines at all:
    code-only sends a Code line; otherwise Username/Password lines
    plus a 2FA line only when present. No password-change advice and
    no do-not-share advice are appended, for any account type.

v2.0.2 change (why the channel button could never open the bot):
  * The channel post button was a callback button, which NEVER opens a
    bot chat — it only sends a silent callback. A user who had never
    pressed START could not receive the DM at all (Telegram 403
    "bot can't initiate conversation with a user").
  * The channel post button is now a URL button
    https://t.me/<botusername>?start=claim, so tapping it OPENS the bot
    chat. /start claim then runs the claim directly in that DM, where
    delivery is guaranteed because the user just started the bot.
  * DM buttons (start/join screens) stay callback buttons — the user is
    already inside the DM there, so callbacks work.
  * On startup the bot refreshes the existing channel post once, so the
    old callback post becomes a URL post without needing a new /post.

Config (same directory, chmod 600):
  .env          BOT_TOKEN=..., ADMIN_ID=...
  config.json   {"channel": "knowledgeshareinghub",
                 "item_name": "CapCut Pro"}
  accounts.json [{"username": "user@example.com", "password": "....",
                  "twofa": ""}, ...]   (twofa optional, may be empty)
  state.db      created automatically (claims + ever_claimed +
                giveaway message id + update offset)
  bot_version   written by the bot on startup (manager app reads it)

Stdlib only — no pip packages needed.
"""

import json
import logging
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
ACCOUNTS_PATH = os.path.join(BASE_DIR, "accounts.json")
DB_PATH = os.path.join(BASE_DIR, "state.db")
VERSION_PATH = os.path.join(BASE_DIR, "bot_version")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("capcut-giveaway")

JOINED_STATUSES = {"creator", "administrator", "member", "restricted"}


# ---------------------------------------------------------------- config
def load_env(path):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def normalize_channel(value):
    """Plain channel name, whatever the user pasted.

    Accepts a plain name, "@name", "t.me/name",
    "http://t.me/name" and "https://t.me/name" (with or without a
    trailing slash) and returns just "name". Anything else is
    returned trimmed and unchanged.
    """
    channel = (value or "").strip()
    lowered = channel.lower()
    for prefix in ("https://t.me/", "http://t.me/", "t.me/"):
        if lowered.startswith(prefix):
            channel = channel[len(prefix):]
            lowered = channel.lower()
            break
    channel = channel.strip().lstrip("@").strip().rstrip("/")
    return channel


def load_config(path, env):
    """config.json wins; .env CHANNEL_USERNAME is a legacy fallback."""
    config = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            config = json.load(f)
    channel = config.get("channel") or env.get("CHANNEL_USERNAME", "")
    item_name = config.get("item_name") or "CapCut Pro"
    return {"channel": normalize_channel(channel), "item_name": item_name}


def load_accounts(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    accounts = []
    for item in data:
        username = (
            item.get("username") or item.get("login") or item.get("email") or ""
        )
        password = item.get("password") or ""
        twofa = item.get("twofa") or item.get("2fa") or item.get("totp_secret") or ""
        if username:
            # v2.0.3: code-only entries have an empty password and are
            # valid. Only an empty username is skipped.
            accounts.append(
                {"username": username, "password": password, "twofa": twofa}
            )
    return accounts


# ---------------------------------------------------------------- state
def init_db(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS claims ("
        " user_id INTEGER PRIMARY KEY,"
        " account_index INTEGER NOT NULL,"
        " username TEXT,"
        " claimed_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta ("
        " key TEXT PRIMARY KEY, value TEXT"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ever_claimed ("
        " user_id INTEGER PRIMARY KEY,"
        " username TEXT,"
        " first_claimed_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    # v2.0.4 grandfather migration (one-time, idempotent): only when
    # ever_claimed is still empty do we copy current claims into it.
    # Later claims are added at claim time, never re-copied here, so
    # a Reset (which clears claims only) can never resurrect an old
    # claimer into ever_claimed — and ever_claimed is never cleared.
    ever_count = conn.execute(
        "SELECT COUNT(*) FROM ever_claimed"
    ).fetchone()[0]
    if ever_count == 0:
        conn.execute(
            "INSERT OR IGNORE INTO ever_claimed"
            " (user_id, username, first_claimed_at)"
            " SELECT user_id, username, claimed_at FROM claims"
        )
    conn.commit()


def get_meta(conn, key):
    row = conn.execute(
        "SELECT value FROM meta WHERE key = ?", (key,)
    ).fetchone()
    return row[0] if row else None


def set_meta(conn, key, value):
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def claim_account(conn, user_id, username, total_accounts):
    """Atomic claim. Returns (status, account_index or None).

    status: 'ok' | 'already' | 'blocked_ever' | 'sold_out'
    'already' returns the user's original account_index.
    'blocked_ever' means the user received an account in an earlier
    giveaway (present in ever_claimed, absent from current claims):
    no account is consumed and no current claim is recorded.
    A new claim inserts into BOTH claims and ever_claimed in the
    same transaction, so the two can never diverge.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT account_index FROM claims WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if row:
            conn.execute("COMMIT")
            return "already", row[0]
        ever = conn.execute(
            "SELECT 1 FROM ever_claimed WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if ever:
            conn.execute("COMMIT")
            return "blocked_ever", None
        count = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        if count >= total_accounts:
            conn.execute("COMMIT")
            return "sold_out", None
        conn.execute(
            "INSERT INTO claims (user_id, account_index, username)"
            " VALUES (?, ?, ?)",
            (user_id, count, username or ""),
        )
        conn.execute(
            "INSERT OR IGNORE INTO ever_claimed (user_id, username)"
            " VALUES (?, ?)",
            (user_id, username or ""),
        )
        conn.execute("COMMIT")
        return "ok", count
    except Exception:
        conn.execute("ROLLBACK")
        raise


def remaining_count(conn, total_accounts):
    count = conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
    return max(0, total_accounts - count)


def list_claims(conn):
    return conn.execute(
        "SELECT user_id, username, account_index, claimed_at"
        " FROM claims ORDER BY account_index"
    ).fetchall()


# ---------------------------------------------------------------- Telegram API
class Telegram:
    def __init__(self, token):
        self.base = "https://api.telegram.org/bot%s/" % token

    def call(self, method, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base + method,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if "message is not modified" in body:
                # Refreshing a post whose text+markup are unchanged is
                # normal (e.g. startup refresh), not an error.
                try:
                    return json.loads(body)
                except ValueError:
                    return {"ok": False, "description": body[:300]}
            log.warning("Telegram %s HTTP %s: %s", method, e.code, body[:300])
            try:
                return json.loads(body)
            except ValueError:
                return {"ok": False, "description": body[:300]}
        except Exception as e:  # network error, etc.
            log.warning("Telegram %s error: %s", method, e)
            return {"ok": False, "description": str(e)}

    def get_me(self):
        """Bot's own username (public), or None if the call fails."""
        result = self.call("getMe", {})
        if result.get("ok"):
            return result.get("result", {}).get("username")
        return None

    def send_message(self, chat_id, text, reply_markup=None):
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        return self.call("sendMessage", payload)

    def edit_message(self, chat_id, message_id, text, reply_markup=None):
        payload = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        return self.call("editMessageText", payload)

    def answer_callback(self, callback_query_id, text=""):
        return self.call(
            "answerCallbackQuery",
            {"callback_query_id": callback_query_id, "text": text},
        )

    def is_channel_member(self, channel, user_id):
        """True only for joined statuses; any API failure = not joined."""
        result = self.call(
            "getChatMember",
            {"chat_id": "@" + channel, "user_id": user_id},
        )
        if not result.get("ok"):
            log.warning(
                "getChatMember failed for user %s (bot must be channel admin)",
                user_id,
            )
            return False
        status = result.get("result", {}).get("status", "")
        return status in JOINED_STATUSES


# ---------------------------------------------------------------- messages
def giveaway_text(remaining, total, item_name):
    if remaining <= 0:
        return (
            "🎁 <b>%s Account Giveaway</b>\n\n"
            "❌ ကုန်သွားပါပြီ — %d ခုလုံး ပေးပြီးပါပြီ।"
            % (item_name, total)
        )
    return (
        "🎁 <b>%s Account Giveaway</b>\n\n"
        "• စုစုပေါင်း: %d ခု\n"
        "• ကျန်: <b>%d ခု</b>\n"
        "• ဦးသူရ, တစ်ယောက်ကို တစ်ခုပဲရမယ်\n"
        "• Channel join ထားမှ claim လုပ်လို့ရမယ်\n\n"
        "Claim လုပ်ဖို့ အောက်က button ကို နှိပ်ပါ 👇"
        % (item_name, total, remaining)
    )


def post_button(bot_username, item_name):
    """Channel post button: a URL button that OPENS the bot chat.

    Callback buttons never open a chat, so a channel post must use a
    URL button with a start payload; /start claim then claims in DM.
    Returns None when the username is unknown (fail-closed: never post
    a button that cannot open the bot).
    """
    if not bot_username:
        return None
    return {
        "inline_keyboard": [
            [
                {
                    "text": "🎁 Claim %s — Bot ဖွင့်" % item_name,
                    "url": "https://t.me/%s?start=claim" % bot_username,
                }
            ]
        ]
    }


def join_button(channel):
    return {
        "inline_keyboard": [
            [
                {
                    "text": "📢 Channel ကို Join ပါ",
                    "url": "https://t.me/" + channel,
                }
            ],
            [{"text": "🎁 Join ပြီးပြီ, Claim လုပ်မယ်", "callback_data": "claim"}],
        ]
    }


def start_button(channel, item_name):
    return {
        "inline_keyboard": [
            [{"text": "🎁 Claim %s" % item_name, "callback_data": "claim"}],
            [
                {
                    "text": "📢 Channel",
                    "url": "https://t.me/" + channel,
                }
            ],
        ]
    }


# ---------------------------------------------------------------- bot
class GiveawayBot:
    def __init__(self, env, config, accounts):
        self.tg = Telegram(env["BOT_TOKEN"])
        self.bot_username = self.tg.get_me()
        if self.bot_username:
            log.info("bot username: @%s", self.bot_username)
        else:
            log.warning("getMe failed — channel posts cannot use a URL button until restart")
        self.admin_id = int(env["ADMIN_ID"]) if env.get("ADMIN_ID") else None
        self.channel = config["channel"]
        self.item_name = config["item_name"]
        self.accounts = accounts
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        init_db(self.conn)

    def remaining(self):
        return remaining_count(self.conn, len(self.accounts))

    def refresh_giveaway_post(self):
        raw = get_meta(self.conn, "giveaway_message")
        if not raw:
            return
        try:
            chat_id, message_id = raw.split(":", 1)
            message_id = int(message_id)
        except ValueError:
            return
        if not self.bot_username:
            log.warning("refresh skipped: bot username unknown")
            return
        left = self.remaining()
        markup = post_button(self.bot_username, self.item_name) if left > 0 else None
        self.tg.edit_message(
            chat_id, message_id,
            giveaway_text(left, len(self.accounts), self.item_name), markup
        )

    def do_claim(self, user_id, username):
        """Full claim flow for one user. Sends all replies by DM."""
        if not self.tg.is_channel_member(self.channel, user_id):
            self.tg.send_message(
                user_id,
                "⚠️ အရင်ဆုံး channel ကို join ထားမှ claim လုပ်လို့ရမယ်။\n"
                "Join ပြီးရင် Claim button ကို ပြန်နှိပ်ပါ။",
                join_button(self.channel),
            )
            log.info("claim blocked (not joined): user %s", user_id)
            return

        status, index = claim_account(
            self.conn, user_id, username, len(self.accounts)
        )
        if status == "sold_out":
            self.tg.send_message(
                user_id,
                "❌ စိတ်မကောင်းပါဘူး, %s account တွေ ကုန်သွားပါပြီ။"
                % self.item_name
            )
            log.info("claim sold_out: user %s", user_id)
            return

        if status == "blocked_ever":
            # v2.0.4: received an account in an earlier giveaway, so
            # no account this time. No current claim is recorded, no
            # account is consumed, and the post is NOT refreshed
            # (its count is unchanged) — we return before the
            # refresh call at the end of do_claim.
            self.tg.send_message(
                user_id,
                "ℹ️ သင် အရင် giveaway မှာ account တစ်ခု ရပြီးသားပါ — "
                "ဒီတစ်ခါ giveaway မှာ ထပ်မရပါဘူး။"
            )
            log.info("claim blocked (ever-claimed): user %s", user_id)
            return

        account = self.accounts[index]
        if status == "already":
            intro = (
                "ℹ️ သင်က account တစ်ခု ယူပြီးသားပါ — ဒုတိယအကောင့် မရပါဘူး။\n"
                "သင့်ရဲ့ အကောင့်ပဲ ပြန်ပို့ပေးလိုက်ပါတယ် 👇\n\n"
            )
        else:
            intro = "🎉 ရပါပြီ! သင့်ရဲ့ %s account 👇\n\n" % self.item_name
            log.info("claim ok: user %s -> account #%d", user_id, index + 1)
        twofa_line = ""
        if account.get("twofa"):
            twofa_line = "2FA: <code>%s</code>\n" % account["twofa"]
        # v2.0.3: DM is intro + credentials ONLY, no footer lines.
        # (The 2.0.1 % formatting lesson still applies: % must apply
        # to the WHOLE message, not just the last string literal.)
        if not account.get("password"):
            dm_text = intro + "Code: <code>%s</code>\n" % account["username"]
            if twofa_line:
                dm_text += twofa_line
        else:
            dm_text = (
                intro
                + "Username: <code>%s</code>\nPassword: <code>%s</code>\n"
                + twofa_line
            ) % (account["username"], account["password"])
        self.tg.send_message(user_id, dm_text)
        self.refresh_giveaway_post()

    def handle_message(self, message):
        chat = message.get("chat", {})
        chat_type = chat.get("type", "")
        user = message.get("from", {})
        user_id = user.get("id")
        username = user.get("username", "")
        text = (message.get("text") or "").strip()
        if not user_id or not text:
            return

        if text.startswith("/start") or text.startswith("/claim"):
            if chat_type != "private":
                self.tg.send_message(
                    chat["id"],
                    "DM မှာ claim လုပ်ပါ — account ကို private DM နဲ့ပဲ ပို့ပါတယ်။",
                )
                return
            parts = text.split(None, 1)
            payload = parts[1].strip() if len(parts) > 1 else ""
            if payload == "claim":
                # Came from the channel URL button: the user just pressed
                # START, so DM delivery is guaranteed — claim right here.
                self.do_claim(user_id, username)
                return
            self.tg.send_message(
                user_id,
                giveaway_text(self.remaining(), len(self.accounts), self.item_name),
                start_button(self.channel, self.item_name),
            )
            return

        if text.startswith("/remaining"):
            self.tg.send_message(
                user_id,
                "ကျန်တဲ့ %s account: <b>%d / %d</b>"
                % (self.item_name, self.remaining(), len(self.accounts)),
            )
            return

        if text.startswith("/status"):
            if self.admin_id is None or user_id != self.admin_id:
                self.tg.send_message(user_id, "Admin ပဲ သုံးလို့ရတဲ့ command ပါ။")
                return
            rows = list_claims(self.conn)
            ever_total = self.conn.execute(
                "SELECT COUNT(*) FROM ever_claimed"
            ).fetchone()[0]
            lines = [
                "📊 Giveaway status: %d / %d ပေးပြီး, %d ခု ကျန်"
                % (
                    len(rows),
                    len(self.accounts),
                    self.remaining(),
                ),
                "စုစုပေါင်း ရဖူးသူ: %d ယောက်" % ever_total,
            ]
            for uid, uname, idx, when in rows:
                lines.append(
                    "#%d — user %s (@%s) — %s"
                    % (idx + 1, uid, uname or "-", when)
                )
            self.tg.send_message(user_id, "\n".join(lines) or "မရှိသေးပါ။")
            return

        if text.startswith("/post"):
            if self.admin_id is None or user_id != self.admin_id:
                self.tg.send_message(user_id, "Admin ပဲ သုံးလို့ရတဲ့ command ပါ။")
                return
            if not self.bot_username:
                self.tg.send_message(
                    user_id,
                    "❌ Bot username မရသေးဘူး — bot ကို restart လုပ်ပြီး /post ကို ပြန်လုပ်ပါ။",
                )
                return
            result = self.tg.send_message(
                "@" + self.channel,
                giveaway_text(self.remaining(), len(self.accounts), self.item_name),
                post_button(self.bot_username, self.item_name),
            )
            if result.get("ok"):
                msg = result["result"]
                set_meta(
                    self.conn,
                    "giveaway_message",
                    "%s:%s" % (msg["chat"]["id"], msg["message_id"]),
                )
                self.tg.send_message(
                    user_id, "✅ Channel မှာ giveaway post တင်ပြီးပါပြီ။"
                )
            else:
                self.tg.send_message(
                    user_id,
                    "❌ Channel မှာ post တင်လို့ မရဘူး — "
                    "bot ကို channel admin (Post Messages) အဖြစ် ထည့်ထားလား စစ်ပါ။",
                )
            return

    def handle_callback(self, callback):
        user = callback.get("from", {})
        user_id = user.get("id")
        username = user.get("username", "")
        data = callback.get("data", "")
        self.tg.answer_callback(callback["id"])
        if not user_id or data != "claim":
            return
        # Credentials always go by private DM, never to the channel/group
        # where the button was pressed.
        self.do_claim(user_id, username)

    def run(self):
        offset = get_meta(self.conn, "update_offset")
        offset = int(offset) if offset else 0
        log.info(
            "polling started: %d accounts, %d remaining, channel @%s",
            len(self.accounts),
            self.remaining(),
            self.channel,
        )
        while True:
            result = self.tg.call(
                "getUpdates",
                {"offset": offset, "timeout": 25, "allowed_updates": ["message", "callback_query"]},
            )
            if not result.get("ok"):
                time.sleep(3)
                continue
            for update in result.get("result", []):
                offset = update["update_id"] + 1
                set_meta(self.conn, "update_offset", str(offset))
                try:
                    if "message" in update:
                        self.handle_message(update["message"])
                    elif "callback_query" in update:
                        self.handle_callback(update["callback_query"])
                except Exception as e:
                    log.warning("update %s failed: %s", update["update_id"], e)


def main():
    env = load_env(ENV_PATH)
    token = env.get("BOT_TOKEN", "")
    if not token:
        log.error("BOT_TOKEN missing in .env — fill it first, then start the service.")
        sys.exit(1)
    config = load_config(CONFIG_PATH, env)
    if not config["channel"]:
        log.error("channel missing in config.json — fill it first, then start the service.")
        sys.exit(1)
    if not os.path.exists(ACCOUNTS_PATH):
        log.error("accounts.json missing — fill it first, then start the service.")
        sys.exit(1)
    accounts = load_accounts(ACCOUNTS_PATH)
    if not accounts:
        log.error("accounts.json is empty — fill it with the giveaway accounts first.")
        sys.exit(1)
    with open(VERSION_PATH, "w", encoding="utf-8") as f:
        f.write(BOT_VERSION)
    log.info(
        "bot v%s: %d accounts, item=%s, channel=@%s (values never logged)",
        BOT_VERSION,
        len(accounts),
        config["item_name"],
        config["channel"],
    )
    bot = GiveawayBot(env, config, accounts)
    try:
        bot.refresh_giveaway_post()
    except Exception as e:
        log.warning("startup post refresh failed (ignored): %s", e)
    bot.run()


if __name__ == "__main__":
    main()
