#!/usr/bin/env python3
"""KSH Channel Key bot — posts a free Outline key to a Telegram channel.

Runs on the Outline VPS itself (root), as a
systemd timer (every 15 minutes) — the same pattern as
the KSH Admin rotation agent. No Worker, no webhook, no domain needed.

Rules (Yan's spec, 2026-11-03):
- One current key, Free, data limit from config (default 100 GB,
  set by the app's Install Bot; Yan confirmed 100 GB, 2026-11-03).
- First key: created and posted immediately on Start (no 24h wait).
- Later keys: only when the current key's usage reaches the limit, AND
  at least 24 hours have passed since the last channel post. If the
  key is exhausted within 24h of the last post, wait until the 24h
  mark (the timer retries every 15 minutes, so the post lands
  shortly after the mark) — do NOT post early.
- Post order is fail-closed: create new key -> post to channel ->
  only then delete the old key and adopt the new one. If the post
  fails, the new key is kept as pending and retried first on the
  next run — never create a second orphan key.
- Post includes the posting date + time in Myanmar time
  (Asia/Yangon, UTC+6:30, no DST), and the key inside a <code> block
  so it can be copied in Telegram. Extra message texts, when Yan
  provides them, go in config["extra_text"] and are appended
  verbatim after the key block.
- Secrets (bot token, Outline apiUrl, cert, accessUrl) are NEVER
  printed to logs. Logs contain masked key ids (first 8 chars),
  byte counts, and timestamps only.

Manager build (v1.4.4): same bot, adapted for the Bot Manager's
one-file install (bots/keypost/ in yanlin86/For-My-Bot-code).
Differences from the Key Channel app's copy:
- All bot-owned files live next to this script (config.json,
  state.json, status.json, .lock), so it runs from any install
  directory (/opt/bots/keypost/ via the Manager, or the legacy
  /opt/ksh-channel-bot/).
- config.json holds secrets + settings ONLY (what the Manager
  form writes). Mutable runtime state lives in state.json,
  which the Manager never touches — a Manager Save can no
  longer wipe the current key, counter, or pending key.
- api_url / cert_sha256 are NOT required in config.json: when
  missing they are derived from /opt/outline/access.txt at
  load (and re-derived every run). Outline must be installed
  on the SAME VPS; access.txt is never written.
- QR codes use the embedded Nayuki qrcodegen (stdlib-only,
  MIT) instead of the vendored qrcode/ package tree — the
  Manager installs this single file only.
- The /stop admin command disables this install's own timer
  (install directory name + ".timer").

Config: <install-dir>/config.json (chmod 600), written by the
Bot Manager from its form. A separate, secret-free status file
<install-dir>/status.json reports the bot state.
"""
from __future__ import annotations  # required by the embedded Nayuki qrcodegen: its annotations reference QrCode.Ecc before it is defined
import argparse
import fcntl
import hashlib
import html
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# Manager build: bot-owned files live next to this script, so the bot
# works from any install directory (/opt/bots/<id>/ via the Manager,
# or the legacy /opt/ksh-channel-bot/). Outline paths (ACCESS_TXT,
# DISK_CERT) stay absolute — the bot must run on a VPS with Outline.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
STATUS_PATH = os.path.join(BASE_DIR, "status.json")
STATE_PATH = os.path.join(BASE_DIR, "state.json")
SERVICE_TIMER = os.path.basename(BASE_DIR) + ".timer"
BOT_VERSION = "1.4.4"
ACCESS_TXT = "/opt/outline/access.txt"
DISK_CERT = "/opt/outline/persisted-state/shadowbox-selfsigned.crt"
TIMEOUT = 30

# Config vs state split (Manager-compatible):
# - config.json: secrets + settings written by the Manager form.
#   The Manager's Save rewrites this file from the form, so nothing
#   the bot mutates at runtime may live here.
# - state.json: mutable runtime state. The Manager never touches it.
SETTINGS_FIELDS = (
    "bot_token", "admin_id", "channel_id", "api_url", "cert_sha256",
    "extra_text", "server_location", "key_domain", "key_name_base",
    "limit_gb", "bot_version",
)
STATE_FIELDS = (
    "current_key_id", "current_key_name",
    "pending_new_key_id", "pending_new_access_url", "pending_new_key_name",
    "last_post_iso", "last_channel_message_id", "last_channel_message_type",
    "last_post_display_url", "last_post_key_name",
    "last_usage_percent", "last_usage_edit_iso", "usage_bar_style",
    "key_counter", "tg_offset",
)
WAIT_SECONDS = 24 * 3600               # 24 hours
MYANMAR_TZ = timezone(timedelta(hours=6, minutes=30))
USER_AGENT = "KSH-ChannelBot/1.0"


def log(msg):
    print(f"[ksh-channel] {msg}", flush=True)


def mask_key(key_id):
    return (key_id or "")[:8]


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)
    for field in ("bot_token", "admin_id", "channel_id"):
        if not cfg.get(field):
            raise ValueError(f"config missing field: {field}")
    # api_url / cert_sha256 are NOT form fields, so a Manager Save
    # wipes them from config.json. Derive them from Outline's
    # access.txt whenever they are missing (re-derived every run
    # in _main_locked as well). access.txt is never written.
    if not cfg.get("api_url") or not cfg.get("cert_sha256"):
        try:
            api_url, cert = parse_access_txt()
        except Exception as e:
            raise ValueError(
                "config missing api_url/cert_sha256 and "
                f"{ACCESS_TXT} is not readable ({e}) — "
                "Outline must be installed on this VPS first"
            ) from e
        cfg["api_url"] = api_url
        cfg["cert_sha256"] = cert
    # Runtime state lives in state.json (Manager never touches it).
    # A legacy merged config.json may still carry state fields;
    # they are picked up here and split out on the next save.
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            state = json.load(f)
        if isinstance(state, dict):
            cfg.update(state)
    except FileNotFoundError:
        pass
    except Exception as e:
        log(f"WARNING: state.json unreadable, using config state: {e}")
    cfg.setdefault("current_key_id", "")
    cfg.setdefault("current_key_name", "")
    cfg.setdefault("pending_new_key_id", "")
    cfg.setdefault("pending_new_access_url", "")
    cfg.setdefault("pending_new_key_name", "")
    cfg.setdefault("last_post_iso", "")
    cfg.setdefault("extra_text", "")
    # v1.1 fields, set by the app's Install Bot (defaults keep v1 working):
    cfg.setdefault("server_location", "")
    cfg.setdefault("key_domain", "")
    cfg.setdefault("bot_version", BOT_VERSION)
    cfg.setdefault("last_channel_message_id", "")
    cfg.setdefault("last_channel_message_type", "text")
    cfg.setdefault("last_post_display_url", "")
    cfg.setdefault("last_post_key_name", "")
    cfg.setdefault("last_usage_percent", 0)
    cfg.setdefault("last_usage_edit_iso", "")
    cfg.setdefault("usage_bar_style", "remaining")
    cfg.setdefault("key_name_base", "kshfree")
    cfg.setdefault("limit_gb", 100)
    cfg.setdefault("key_counter", 0)
    cfg.setdefault("tg_offset", 0)
    return cfg


def limit_bytes(cfg):
    try:
        gb = int(cfg.get("limit_gb", 100) or 100)
    except (TypeError, ValueError):
        gb = 100
    if gb <= 0:
        gb = 100
    return gb * 1024 ** 3


def limit_gb(cfg):
    return limit_bytes(cfg) // (1024 ** 3)


def display_access_url(cfg, access_url, key_name=""):
    """Channel-post link: domain instead of IP, plus #key_name.

    The Outline server's own accessUrl uses its detected IP. For the
    channel, replace that IP host with the configured domain (which
    must resolve to the same VPS IP, e.g. sg3.kshinfo.works ->
    168.144.130.0) so the key keeps working if the VPS IP changes
    by repointing the domain. Append #key_name so the Outline app
    shows the key name on import (the server-side name alone does
    not travel in the ss link). If no domain is configured, the IP
    link is used unchanged.
    """
    url = (access_url or "").strip()
    domain = str(cfg.get("key_domain") or "").strip()
    if domain and "@" in url:
        at = url.index("@")
        slash = url.find("/", at)
        if slash == -1:
            hostport = url[at + 1:]
            rest = ""
        else:
            hostport = url[at + 1:slash]
            rest = url[slash:]
        if ":" in hostport:
            port = hostport.split(":", 1)[1]
            new_hostport = f"{domain}:{port}"
        else:
            new_hostport = domain
        url = url[:at + 1] + new_hostport + rest
    # Strip any existing fragment, then add #key_name.
    if "#" in url:
        url = url.split("#", 1)[0]
    if key_name:
        from urllib.parse import quote
        url = url + "#" + quote(str(key_name), safe="")
    return url


class BotLock:
    """Single-run lock: if another bot run is already active, exit.

    Prevents the double-Start race that posted two keys at 19:24 on
    2026-11-03 (two concurrent check-once runs both saw an empty
    current key and both created + posted, both named kshfree).
    The lock is held for the whole run and released on exit.
    """
    def __init__(self):
        self.f = None
        self.path = os.path.join(BASE_DIR, ".lock")

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.f = open(self.path, "a+")
        try:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.f.close()
            self.f = None
            raise
        return self

    def __exit__(self, *args):
        if self.f is not None:
            try:
                fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            finally:
                self.f.close()
                self.f = None
        return False


def next_key_name(cfg):
    """Incrementing key name: base, base1, base2, ...

    The counter advances when a key is CREATED (not when it is
    posted), so a pending key keeps its name on retry and the next
    created key never reuses a name. The caller saves the config
    right after creation (with the pending key), so the counter
    survives a post failure.
    """
    base = str(cfg.get("key_name_base") or "kshfree").strip() or "kshfree"
    try:
        counter = int(cfg.get("key_counter", 0) or 0)
    except (TypeError, ValueError):
        counter = 0
    name = base if counter == 0 else f"{base}{counter}"
    cfg["key_counter"] = counter + 1
    return name


def _atomic_write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def save_config(cfg):
    # Split on write: settings (+secrets) -> config.json, mutable
    # runtime state -> state.json. The Manager's Save rewrites
    # config.json from the form, so state must never live there.
    settings = {k: cfg.get(k) for k in SETTINGS_FIELDS if k in cfg}
    state = {k: cfg.get(k) for k in STATE_FIELDS if k in cfg}
    _atomic_write_json(CONFIG_PATH, settings)
    _atomic_write_json(STATE_PATH, state)


def write_status(cfg, outline_installed=True, error=""):
    # Secret-free: no token, no apiUrl, no accessUrl, no cert.
    try:
        last_post = cfg.get("last_post_iso", "")
        next_earliest = ""
        if last_post:
            dt = datetime.fromisoformat(last_post.replace("Z", "+00:00"))
            nxt = dt + timedelta(seconds=WAIT_SECONDS)
            next_earliest = nxt.astimezone(MYANMAR_TZ).strftime("%Y-%m-%d %H:%M")
        status = {
            "bot_version": BOT_VERSION,
            "outline_installed": outline_installed,
            "current_key_exists": bool(cfg.get("current_key_id")),
            "current_key_id_masked": mask_key(cfg.get("current_key_id", "")),
            "current_key_name": cfg.get("current_key_name", ""),
            "limit_gb": limit_gb(cfg),
            "pending_key_exists": bool(cfg.get("pending_new_key_id")),
            "last_post_iso": last_post,
            "last_post_myanmar": (
                datetime.fromisoformat(last_post.replace("Z", "+00:00"))
                .astimezone(MYANMAR_TZ).strftime("%Y-%m-%d %H:%M")
                if last_post else ""
            ),
            "next_post_earliest_myanmar": next_earliest,
            "error": error,
        }
        with open(STATUS_PATH, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=2)
            f.write("\n")
        os.chmod(STATUS_PATH, 0o644)
    except Exception as e:
        log(f"WARNING: status write failed: {type(e).__name__}")


def parse_access_txt():
    with open(ACCESS_TXT, encoding="utf-8") as f:
        text = f.read()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and obj.get("apiUrl") and obj.get("certSha256"):
            return str(obj["apiUrl"]).strip(), str(obj["certSha256"]).strip().lower()
    except ValueError:
        pass
    api_url = ""
    cert = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("apiUrl:"):
            api_url = line[len("apiUrl:"):].strip()
        elif line.startswith("certSha256:"):
            cert = line[len("certSha256:"):].strip().lower()
    if not api_url or not cert:
        raise ValueError("access.txt did not contain apiUrl + certSha256")
    return api_url, cert


def live_fingerprint(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


def resolve_cert_pin(api_url, access_cert):
    """Disk-cert pin when it matches the live cert, else access.txt.

    Same proven rule as the rotation agent v2.1: after a backup
    restore, access.txt can be stale, while the on-disk shadowbox
    cert still matches the live cert. access.txt is never written.
    """
    parsed = urllib.parse.urlparse(api_url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    disk_hash = ""
    try:
        der = ssl.PEM_cert_to_DER_cert(open(DISK_CERT, encoding="utf-8").read())
        disk_hash = hashlib.sha256(der).hexdigest()
    except Exception:
        pass
    live_hash = ""
    for h in ("127.0.0.1", host):
        if not h:
            continue
        try:
            live_hash = live_fingerprint(h, port)
            break
        except Exception:
            continue
    if disk_hash and live_hash and disk_hash == live_hash:
        return disk_hash
    return access_cert.lower().replace(":", "").replace(" ", "")


def outline_request(cfg, method, path, body=None):
    url = cfg["api_url"].rstrip("/") + "/" + path.lstrip("/")
    data = None
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=TIMEOUT) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Outline API HTTP {e.code}: {detail}") from e
    # Fingerprint check on a fresh handshake before trusting the body.
    parsed = urllib.parse.urlparse(cfg["api_url"])
    host = parsed.hostname or ""
    port = parsed.port or 443
    actual = live_fingerprint(host, port)
    if actual != cfg["cert_sha256"].lower():
        raise RuntimeError("Outline cert fingerprint mismatch — aborting, not trusting response")
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def create_new_key(cfg):
    created = outline_request(cfg, "POST", "access-keys")
    key_id = created["id"]
    outline_request(cfg, "PUT", f"access-keys/{key_id}/data-limit",
                    {"limit": {"bytes": limit_bytes(cfg)}})
    key_name = next_key_name(cfg)
    outline_request(cfg, "PUT", f"access-keys/{key_id}/name",
                    {"name": key_name})
    log(f"created key {mask_key(key_id)} named {key_name} "
        f"({limit_gb(cfg)} GB)")
    # The created key's accessUrl is in the POST response; refetch to
    # be safe if the shape differs.
    if created.get("accessUrl"):
        return key_id, created["accessUrl"], key_name
    keys = outline_request(cfg, "GET", "access-keys")
    for k in keys.get("accessKeys", []):
        if k.get("id") == key_id:
            return key_id, k.get("accessUrl", ""), key_name
    raise RuntimeError("created key has no accessUrl")


def delete_key(cfg, key_id):
    if not key_id:
        return
    try:
        outline_request(cfg, "DELETE", f"access-keys/{key_id}")
        log(f"deleted old key {mask_key(key_id)}")
    except Exception as e:
        log(f"WARNING: old key delete failed (new key is live): {e}")


def tg_request(cfg, method, payload):
    url = f"https://api.telegram.org/bot{cfg['bot_token']}/{method}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Telegram HTTP {e.code}: {detail}") from e


def myanmar_now():
    return datetime.now(MYANMAR_TZ)


def usage_bar(cfg, used_bytes):
    """Text usage bar for the channel post, e.g. 🟩🟩🟩🟩🟩🟩🟩🟩⬜⬜ 20%.
    Green = REMAINING data: a fresh key shows 10 green, green shrinks
    as data is used, an exhausted key shows 0 green. The numeric text
    still reports USED percent / used GB, only the blocks are inverted."""
    limit = limit_bytes(cfg)
    if limit <= 0:
        return ""
    percent = int((used_bytes / limit) * 100)
    percent = max(0, min(100, percent))
    remaining_percent = 100 - percent
    filled = int(round(remaining_percent / 10))
    filled = max(0, min(10, filled))
    bar = "🟩" * filled + "⬜" * (10 - filled)
    used_gb = used_bytes / (1024 ** 3)
    return f"{bar} {percent}% ({used_gb:.1f}GB / {limit_gb(cfg)}GB)"


def build_post_text(cfg, display_url, key_name, used_bytes=0, post_myanmar=None):
    """Full channel post text. How-to lives in an expandable blockquote
    so the post stays short visually, with complete steps on expand."""
    if post_myanmar is None:
        post_myanmar = myanmar_now().strftime("%Y-%m-%d %H:%M")
    location = str(cfg.get("server_location") or "").strip()
    loc_prefix = f"{location} " if location else ""
    limit = limit_gb(cfg)
    lines = [
        "<b>🔑 Outline အသုံးပြုသူများအတွက်</b>",
        "",
        f"<b>{html.escape(loc_prefix)}{limit}GB key</b> ကို copy ကူးယူပြီး အသုံးပြုနိုင်ပါပြီ",
        "",
    ]
    if key_name:
        lines.append(f"<b>Key: {html.escape(key_name)}</b>")
    lines += [
        f"<b>📅 {post_myanmar}</b>",
        f"Usage: {usage_bar(cfg, used_bytes)}",
        "",
        f"<code>{html.escape(display_url, quote=False)}</code>",
        "",
        "<b>Outline app ထဲမှာ key ထည့်ပုံ:</b>",
        "<blockquote expandable>"
        "1. Outline app ဖွင့် → + နှိပ် (မရှိသေးရင် Play Store / App Store ကနေ Outline install လုပ်)\n"
        "2. Key စာကို ဖိပြီး copy လုပ် → Outline ထဲ paste လုပ်, ဒါမှမဟုတ် QR code ကို scan လုပ် (လက်နဲ့ ရိုက်မထည့်ပါနဲ့)\n"
        "3. Connect နှိပ် → VPN permission Allow လုပ် (Android: OK, iOS: passcode / Face ID)\n"
        "4. Connected ဆို သုံးလို့ရပြီ\n"
        "5. သုံးမရရင်: Internet စစ်, နောက်ဆုံး key ပဲ သုံးပါ, Disconnect → ပြန်ချိတ်, မရရင် key ဖျက် → အသစ် ထည့်\n"
        f"6. Shared key, {limit}GB ကုန်ရင် bot က key အသစ် auto တင်မယ်, အဟောင်း key သုံးမရတော့ဘူး"
        "</blockquote>",
    ]
    extra = (cfg.get("extra_text") or "").strip()
    if extra:
        lines.append("")
        lines.append(extra)
    return "\n".join(lines)


def buy_keyboard():
    """Inline Buy buttons — replaced the old Copy Key button (v1.4.4).
    Buy Admin opens a DM with the admin (@YanNaingLyn); Buy Bot opens
    the KeyShop bot (@KeyShopMmBot) where keys are sold. URL buttons
    only — no key data involved. Users copy the key by long-pressing
    the code block in the post text, or scan the QR photo."""
    return {"inline_keyboard": [[
        {"text": "🛒 Buy Admin", "url": "https://t.me/YanNaingLyn"},
        {"text": "🤖 Buy Bot", "url": "https://t.me/KeyShopMmBot"},
    ]]}


# ======================================================================
# Embedded QR encoder — Project Nayuki "QR Code generator library
# (Python)", MIT License, https://www.nayuki.io/page/qr-code-generator-library
# Single-file, stdlib-only. Vendored here so the bot stays a single
# file for the Bot Manager's one-file install (the live bot used a
# vendored qrcode/ package tree instead). Only QrCode.encode_text /
# get_size / get_module are used, in make_qr_png_bytes below.
# Tabs expanded to 4 spaces; the `from __future__ import annotations`
# line was moved to the top of this file.
# ======================================================================
# 
# QR Code generator library (Python)
# 
# Copyright (c) Project Nayuki. (MIT License)
# https://www.nayuki.io/page/qr-code-generator-library
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.
# 

import collections, itertools, re
from collections.abc import Sequence
from typing import Optional, Union


# ---- QR Code symbol class ----

class QrCode:
    """A QR Code symbol, which is a type of two-dimension barcode.
    Invented by Denso Wave and described in the ISO/IEC 18004 standard.
    Instances of this class represent an immutable square grid of dark and light cells.
    The class provides static factory functions to create a QR Code from text or binary data.
    The class covers the QR Code Model 2 specification, supporting all versions (sizes)
    from 1 to 40, all 4 error correction levels, and 4 character encoding modes.
    
    Ways to create a QR Code object:
    - High level: Take the payload data and call QrCode.encode_text() or QrCode.encode_binary().
    - Mid level: Custom-make the list of segments and call QrCode.encode_segments().
    - Low level: Custom-make the array of data codeword bytes (including
      segment headers and final padding, excluding error correction codewords),
      supply the appropriate version number, and call the QrCode() constructor.
    (Note that all ways require supplying the desired error correction level.)"""
    
    # ---- Static factory functions (high level) ----
    
    @staticmethod
    def encode_text(text: str, ecl: QrCode.Ecc) -> QrCode:
        """Returns a QR Code representing the given Unicode text string at the given error correction level.
        As a conservative upper bound, this function is guaranteed to succeed for strings that have 738 or fewer
        Unicode code points (not UTF-16 code units) if the low error correction level is used. The smallest possible
        QR Code version is automatically chosen for the output. The ECC level of the result may be higher than the
        ecl argument if it can be done without increasing the version."""
        segs: list[QrSegment] = QrSegment.make_segments(text)
        return QrCode.encode_segments(segs, ecl)
    
    
    @staticmethod
    def encode_binary(data: Union[bytes,Sequence[int]], ecl: QrCode.Ecc) -> QrCode:
        """Returns a QR Code representing the given binary data at the given error correction level.
        This function always encodes using the binary segment mode, not any text mode. The maximum number of
        bytes allowed is 2953. The smallest possible QR Code version is automatically chosen for the output.
        The ECC level of the result may be higher than the ecl argument if it can be done without increasing the version."""
        return QrCode.encode_segments([QrSegment.make_bytes(data)], ecl)
    
    
    # ---- Static factory functions (mid level) ----
    
    @staticmethod
    def encode_segments(segs: Sequence[QrSegment], ecl: QrCode.Ecc, minversion: int = 1, maxversion: int = 40, mask: int = -1, boostecl: bool = True) -> QrCode:
        """Returns a QR Code representing the given segments with the given encoding parameters.
        The smallest possible QR Code version within the given range is automatically
        chosen for the output. Iff boostecl is true, then the ECC level of the result
        may be higher than the ecl argument if it can be done without increasing the
        version. The mask number is either between 0 to 7 (inclusive) to force that
        mask, or -1 to automatically choose an appropriate mask (which may be slow).
        This function allows the user to create a custom sequence of segments that switches
        between modes (such as alphanumeric and byte) to encode text in less space.
        This is a mid-level API; the high-level API is encode_text() and encode_binary()."""
        
        if not (QrCode.MIN_VERSION <= minversion <= maxversion <= QrCode.MAX_VERSION) or not (-1 <= mask <= 7):
            raise ValueError("Invalid value")
        
        # Find the minimal version number to use
        for version in range(minversion, maxversion + 1):
            datacapacitybits: int = QrCode._get_num_data_codewords(version, ecl) * 8  # Number of data bits available
            datausedbits: Optional[int] = QrSegment.get_total_bits(segs, version)
            if (datausedbits is not None) and (datausedbits <= datacapacitybits):
                break  # This version number is found to be suitable
            if version >= maxversion:  # All versions in the range could not fit the given data
                msg: str = "Segment too long"
                if datausedbits is not None:
                    msg = f"Data length = {datausedbits} bits, Max capacity = {datacapacitybits} bits"
                raise DataTooLongError(msg)
        assert datausedbits is not None
        
        # Increase the error correction level while the data still fits in the current version number
        for newecl in (QrCode.Ecc.MEDIUM, QrCode.Ecc.QUARTILE, QrCode.Ecc.HIGH):  # From low to high
            if boostecl and (datausedbits <= QrCode._get_num_data_codewords(version, newecl) * 8):
                ecl = newecl
        
        # Concatenate all segments to create the data bit string
        bb = _BitBuffer()
        for seg in segs:
            bb.append_bits(seg.get_mode().get_mode_bits(), 4)
            bb.append_bits(seg.get_num_chars(), seg.get_mode().num_char_count_bits(version))
            bb.extend(seg._bitdata)
        assert len(bb) == datausedbits
        
        # Add terminator and pad up to a byte if applicable
        datacapacitybits = QrCode._get_num_data_codewords(version, ecl) * 8
        assert len(bb) <= datacapacitybits
        bb.append_bits(0, min(4, datacapacitybits - len(bb)))
        bb.append_bits(0, -len(bb) % 8)  # Note: Python's modulo on negative numbers behaves better than C family languages
        assert len(bb) % 8 == 0
        
        # Pad with alternating bytes until data capacity is reached
        for padbyte in itertools.cycle((0xEC, 0x11)):
            if len(bb) >= datacapacitybits:
                break
            bb.append_bits(padbyte, 8)
        
        # Pack bits into bytes in big endian
        datacodewords = bytearray([0] * (len(bb) // 8))
        for (i, bit) in enumerate(bb):
            datacodewords[i >> 3] |= bit << (7 - (i & 7))
        
        # Create the QR Code object
        return QrCode(version, ecl, datacodewords, mask)
    
    
    # ---- Private fields ----
    
    # The version number of this QR Code, which is between 1 and 40 (inclusive).
    # This determines the size of this barcode.
    _version: int
    
    # The width and height of this QR Code, measured in modules, between
    # 21 and 177 (inclusive). This is equal to version * 4 + 17.
    _size: int
    
    # The error correction level used in this QR Code.
    _errcorlvl: QrCode.Ecc
    
    # The index of the mask pattern used in this QR Code, which is between 0 and 7 (inclusive).
    # Even if a QR Code is created with automatic masking requested (mask = -1),
    # the resulting object still has a mask value between 0 and 7.
    _mask: int
    
    # The modules of this QR Code (False = light, True = dark).
    # Immutable after constructor finishes. Accessed through get_module().
    _modules: list[list[bool]]
    
    # Indicates function modules that are not subjected to masking. Discarded when constructor finishes.
    _isfunction: list[list[bool]]
    
    
    # ---- Constructor (low level) ----
    
    def __init__(self, version: int, errcorlvl: QrCode.Ecc, datacodewords: Union[bytes,Sequence[int]], msk: int) -> None:
        """Creates a new QR Code with the given version number,
        error correction level, data codeword bytes, and mask number.
        This is a low-level API that most users should not use directly.
        A mid-level API is the encode_segments() function."""
        
        # Check scalar arguments and set fields
        if not (QrCode.MIN_VERSION <= version <= QrCode.MAX_VERSION):
            raise ValueError("Version value out of range")
        if not (-1 <= msk <= 7):
            raise ValueError("Mask value out of range")
        
        self._version = version
        self._size = version * 4 + 17
        self._errcorlvl = errcorlvl
        
        # Initialize both grids to be size*size arrays of Boolean false
        self._modules    = [[False] * self._size for _ in range(self._size)]  # Initially all light
        self._isfunction = [[False] * self._size for _ in range(self._size)]
        
        # Compute ECC, draw modules
        self._draw_function_patterns()
        allcodewords: bytes = self._add_ecc_and_interleave(bytearray(datacodewords))
        self._draw_codewords(allcodewords)
        
        # Do masking
        if msk == -1:  # Automatically choose best mask
            minpenalty: int = 1 << 32
            for i in range(8):
                self._apply_mask(i)
                self._draw_format_bits(i)
                penalty = self._get_penalty_score()
                if penalty < minpenalty:
                    msk = i
                    minpenalty = penalty
                self._apply_mask(i)  # Undoes the mask due to XOR
        assert 0 <= msk <= 7
        self._mask = msk
        self._apply_mask(msk)  # Apply the final choice of mask
        self._draw_format_bits(msk)  # Overwrite old format bits
        
        del self._isfunction
    
    
    # ---- Accessor methods ----
    
    def get_version(self) -> int:
        """Returns this QR Code's version number, in the range [1, 40]."""
        return self._version
    
    def get_size(self) -> int:
        """Returns this QR Code's size, in the range [21, 177]."""
        return self._size
    
    def get_error_correction_level(self) -> QrCode.Ecc:
        """Returns this QR Code's error correction level."""
        return self._errcorlvl
    
    def get_mask(self) -> int:
        """Returns this QR Code's mask, in the range [0, 7]."""
        return self._mask
    
    def get_module(self, x: int, y: int) -> bool:
        """Returns the color of the module (pixel) at the given coordinates, which is False
        for light or True for dark. The top left corner has the coordinates (x=0, y=0).
        If the given coordinates are out of bounds, then False (light) is returned."""
        return (0 <= x < self._size) and (0 <= y < self._size) and self._modules[y][x]
    
    
    # ---- Private helper methods for constructor: Drawing function modules ----
    
    def _draw_function_patterns(self) -> None:
        """Reads this object's version field, and draws and marks all function modules."""
        # Draw horizontal and vertical timing patterns
        for i in range(self._size):
            self._set_function_module(6, i, i % 2 == 0)
            self._set_function_module(i, 6, i % 2 == 0)
        
        # Draw 3 finder patterns (all corners except bottom right; overwrites some timing modules)
        self._draw_finder_pattern(3, 3)
        self._draw_finder_pattern(self._size - 4, 3)
        self._draw_finder_pattern(3, self._size - 4)
        
        # Draw numerous alignment patterns
        alignpatpos: list[int] = self._get_alignment_pattern_positions()
        numalign: int = len(alignpatpos)
        skips: Sequence[tuple[int,int]] = ((0, 0), (0, numalign - 1), (numalign - 1, 0))
        for i in range(numalign):
            for j in range(numalign):
                if (i, j) not in skips:  # Don't draw on the three finder corners
                    self._draw_alignment_pattern(alignpatpos[i], alignpatpos[j])
        
        # Draw configuration data
        self._draw_format_bits(0)  # Dummy mask value; overwritten later in the constructor
        self._draw_version()
    
    
    def _draw_format_bits(self, mask: int) -> None:
        """Draws two copies of the format bits (with its own error correction code)
        based on the given mask and this object's error correction level field."""
        # Calculate error correction code and pack bits
        data: int = self._errcorlvl.formatbits << 3 | mask  # errCorrLvl is uint2, mask is uint3
        rem: int = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits: int = (data << 10 | rem) ^ 0x5412  # uint15
        assert bits >> 15 == 0
        
        # Draw first copy
        for i in range(0, 6):
            self._set_function_module(8, i, _get_bit(bits, i))
        self._set_function_module(8, 7, _get_bit(bits, 6))
        self._set_function_module(8, 8, _get_bit(bits, 7))
        self._set_function_module(7, 8, _get_bit(bits, 8))
        for i in range(9, 15):
            self._set_function_module(14 - i, 8, _get_bit(bits, i))
        
        # Draw second copy
        for i in range(0, 8):
            self._set_function_module(self._size - 1 - i, 8, _get_bit(bits, i))
        for i in range(8, 15):
            self._set_function_module(8, self._size - 15 + i, _get_bit(bits, i))
        self._set_function_module(8, self._size - 8, True)  # Always dark
    
    
    def _draw_version(self) -> None:
        """Draws two copies of the version bits (with its own error correction code),
        based on this object's version field, iff 7 <= version <= 40."""
        if self._version < 7:
            return
        
        # Calculate error correction code and pack bits
        rem: int = self._version  # version is uint6, in the range [7, 40]
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits: int = self._version << 12 | rem  # uint18
        assert bits >> 18 == 0
        
        # Draw two copies
        for i in range(18):
            bit: bool = _get_bit(bits, i)
            a: int = self._size - 11 + i % 3
            b: int = i // 3
            self._set_function_module(a, b, bit)
            self._set_function_module(b, a, bit)
    
    
    def _draw_finder_pattern(self, x: int, y: int) -> None:
        """Draws a 9*9 finder pattern including the border separator,
        with the center module at (x, y). Modules can be out of bounds."""
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                xx, yy = x + dx, y + dy
                if (0 <= xx < self._size) and (0 <= yy < self._size):
                    # Chebyshev/infinity norm
                    self._set_function_module(xx, yy, max(abs(dx), abs(dy)) not in (2, 4))
    
    
    def _draw_alignment_pattern(self, x: int, y: int) -> None:
        """Draws a 5*5 alignment pattern, with the center module
        at (x, y). All modules must be in bounds."""
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                self._set_function_module(x + dx, y + dy, max(abs(dx), abs(dy)) != 1)
    
    
    def _set_function_module(self, x: int, y: int, isdark: bool) -> None:
        """Sets the color of a module and marks it as a function module.
        Only used by the constructor. Coordinates must be in bounds."""
        assert type(isdark) is bool
        self._modules[y][x] = isdark
        self._isfunction[y][x] = True
    
    
    # ---- Private helper methods for constructor: Codewords and masking ----
    
    def _add_ecc_and_interleave(self, data: bytearray) -> bytes:
        """Returns a new byte string representing the given data with the appropriate error correction
        codewords appended to it, based on this object's version and error correction level."""
        version: int = self._version
        assert len(data) == QrCode._get_num_data_codewords(version, self._errcorlvl)
        
        # Calculate parameter numbers
        numblocks: int = QrCode._NUM_ERROR_CORRECTION_BLOCKS[self._errcorlvl.ordinal][version]
        blockecclen: int = QrCode._ECC_CODEWORDS_PER_BLOCK  [self._errcorlvl.ordinal][version]
        rawcodewords: int = QrCode._get_num_raw_data_modules(version) // 8
        numshortblocks: int = numblocks - rawcodewords % numblocks
        shortblocklen: int = rawcodewords // numblocks
        
        # Split data into blocks and append ECC to each block
        blocks: list[bytes] = []
        rsdiv: bytes = QrCode._reed_solomon_compute_divisor(blockecclen)
        k: int = 0
        for i in range(numblocks):
            dat: bytearray = data[k : k + shortblocklen - blockecclen + (0 if i < numshortblocks else 1)]
            k += len(dat)
            ecc: bytes = QrCode._reed_solomon_compute_remainder(dat, rsdiv)
            if i < numshortblocks:
                dat.append(0)
            blocks.append(dat + ecc)
        assert k == len(data)
        
        # Interleave (not concatenate) the bytes from every block into a single sequence
        result = bytearray()
        for i in range(len(blocks[0])):
            for (j, blk) in enumerate(blocks):
                # Skip the padding byte in short blocks
                if (i != shortblocklen - blockecclen) or (j >= numshortblocks):
                    result.append(blk[i])
        assert len(result) == rawcodewords
        return result
    
    
    def _draw_codewords(self, data: bytes) -> None:
        """Draws the given sequence of 8-bit codewords (data and error correction) onto the entire
        data area of this QR Code. Function modules need to be marked off before this is called."""
        assert len(data) == QrCode._get_num_raw_data_modules(self._version) // 8
        
        i: int = 0  # Bit index into the data
        # Do the funny zigzag scan
        for right in range(self._size - 1, 0, -2):  # Index of right column in each column pair
            if right <= 6:
                right -= 1
            for vert in range(self._size):  # Vertical counter
                for j in range(2):
                    x: int = right - j  # Actual x coordinate
                    upward: bool = (right + 1) & 2 == 0
                    y: int = (self._size - 1 - vert) if upward else vert  # Actual y coordinate
                    if (not self._isfunction[y][x]) and (i < len(data) * 8):
                        self._modules[y][x] = _get_bit(data[i >> 3], 7 - (i & 7))
                        i += 1
                    # If this QR Code has any remainder bits (0 to 7), they were assigned as
                    # 0/false/light by the constructor and are left unchanged by this method
        assert i == len(data) * 8
    
    
    def _apply_mask(self, mask: int) -> None:
        """XORs the codeword modules in this QR Code with the given mask pattern.
        The function modules must be marked and the codeword bits must be drawn
        before masking. Due to the arithmetic of XOR, calling _apply_mask() with
        the same mask value a second time will undo the mask. A final well-formed
        QR Code needs exactly one (not zero, two, etc.) mask applied."""
        if not (0 <= mask <= 7):
            raise ValueError("Mask value out of range")
        masker: collections.abc.Callable[[int,int],int] = QrCode._MASK_PATTERNS[mask]
        for y in range(self._size):
            for x in range(self._size):
                self._modules[y][x] ^= (masker(x, y) == 0) and (not self._isfunction[y][x])
    
    
    def _get_penalty_score(self) -> int:
        """Calculates and returns the penalty score based on state of this QR Code's current modules.
        This is used by the automatic mask choice algorithm to find the mask pattern that yields the lowest score."""
        result: int = 0
        size: int = self._size
        modules: list[list[bool]] = self._modules
        
        # Adjacent modules in row having same color, and finder-like patterns
        for y in range(size):
            runcolor: bool = False
            runx: int = 0
            runhistory = collections.deque([0] * 7, 7)
            for x in range(size):
                if modules[y][x] == runcolor:
                    runx += 1
                    if runx == 5:
                        result += QrCode._PENALTY_N1
                    elif runx > 5:
                        result += 1
                else:
                    self._finder_penalty_add_history(runx, runhistory)
                    if not runcolor:
                        result += self._finder_penalty_count_patterns(runhistory) * QrCode._PENALTY_N3
                    runcolor = modules[y][x]
                    runx = 1
            result += self._finder_penalty_terminate_and_count(runcolor, runx, runhistory) * QrCode._PENALTY_N3
        # Adjacent modules in column having same color, and finder-like patterns
        for x in range(size):
            runcolor = False
            runy: int = 0
            runhistory = collections.deque([0] * 7, 7)
            for y in range(size):
                if modules[y][x] == runcolor:
                    runy += 1
                    if runy == 5:
                        result += QrCode._PENALTY_N1
                    elif runy > 5:
                        result += 1
                else:
                    self._finder_penalty_add_history(runy, runhistory)
                    if not runcolor:
                        result += self._finder_penalty_count_patterns(runhistory) * QrCode._PENALTY_N3
                    runcolor = modules[y][x]
                    runy = 1
            result += self._finder_penalty_terminate_and_count(runcolor, runy, runhistory) * QrCode._PENALTY_N3
        
        # 2*2 blocks of modules having same color
        for y in range(size - 1):
            for x in range(size - 1):
                if modules[y][x] == modules[y][x + 1] == modules[y + 1][x] == modules[y + 1][x + 1]:
                    result += QrCode._PENALTY_N2
        
        # Balance of dark and light modules
        dark: int = sum((1 if cell else 0) for row in modules for cell in row)
        total: int = size**2  # Note that size is odd, so dark/total != 1/2
        # Compute the smallest integer k >= 0 such that (45-5k)% <= dark/total <= (55+5k)%
        k: int = (abs(dark * 20 - total * 10) + total - 1) // total - 1
        assert 0 <= k <= 9
        result += k * QrCode._PENALTY_N4
        assert 0 <= result <= 2568888  # Non-tight upper bound based on default values of PENALTY_N1, ..., N4
        return result
    
    
    # ---- Private helper functions ----
    
    def _get_alignment_pattern_positions(self) -> list[int]:
        """Returns an ascending list of positions of alignment patterns for this version number.
        Each position is in the range [0,177), and are used on both the x and y axes.
        This could be implemented as lookup table of 40 variable-length lists of integers."""
        if self._version == 1:
            return []
        else:
            numalign: int = self._version // 7 + 2
            step: int = (self._version * 8 + numalign * 3 + 5) // (numalign * 4 - 4) * 2
            result: list[int] = [(self._size - 7 - i * step) for i in range(numalign - 1)] + [6]
            return list(reversed(result))
    
    
    @staticmethod
    def _get_num_raw_data_modules(ver: int) -> int:
        """Returns the number of data bits that can be stored in a QR Code of the given version number, after
        all function modules are excluded. This includes remainder bits, so it might not be a multiple of 8.
        The result is in the range [208, 29648]. This could be implemented as a 40-entry lookup table."""
        if not (QrCode.MIN_VERSION <= ver <= QrCode.MAX_VERSION):
            raise ValueError("Version number out of range")
        result: int = (16 * ver + 128) * ver + 64
        if ver >= 2:
            numalign: int = ver // 7 + 2
            result -= (25 * numalign - 10) * numalign - 55
            if ver >= 7:
                result -= 36
        assert 208 <= result <= 29648
        return result
    
    
    @staticmethod
    def _get_num_data_codewords(ver: int, ecl: QrCode.Ecc) -> int:
        """Returns the number of 8-bit data (i.e. not error correction) codewords contained in any
        QR Code of the given version number and error correction level, with remainder bits discarded.
        This stateless pure function could be implemented as a (40*4)-cell lookup table."""
        return QrCode._get_num_raw_data_modules(ver) // 8 \
            - QrCode._ECC_CODEWORDS_PER_BLOCK    [ecl.ordinal][ver] \
            * QrCode._NUM_ERROR_CORRECTION_BLOCKS[ecl.ordinal][ver]
    
    
    @staticmethod
    def _reed_solomon_compute_divisor(degree: int) -> bytes:
        """Returns a Reed-Solomon ECC generator polynomial for the given degree. This could be
        implemented as a lookup table over all possible parameter values, instead of as an algorithm."""
        if not (1 <= degree <= 255):
            raise ValueError("Degree out of range")
        # Polynomial coefficients are stored from highest to lowest power, excluding the leading term which is always 1.
        # For example the polynomial x^3 + 255x^2 + 8x + 93 is stored as the uint8 array [255, 8, 93].
        result = bytearray([0] * (degree - 1) + [1])  # Start off with the monomial x^0
        
        # Compute the product polynomial (x - r^0) * (x - r^1) * (x - r^2) * ... * (x - r^{degree-1}),
        # and drop the highest monomial term which is always 1x^degree.
        # Note that r = 0x02, which is a generator element of this field GF(2^8/0x11D).
        root: int = 1
        for _ in range(degree):  # Unused variable i
            # Multiply the current product by (x - r^i)
            for j in range(degree):
                result[j] = QrCode._reed_solomon_multiply(result[j], root)
                if j + 1 < degree:
                    result[j] ^= result[j + 1]
            root = QrCode._reed_solomon_multiply(root, 0x02)
        return result
    
    
    @staticmethod
    def _reed_solomon_compute_remainder(data: bytes, divisor: bytes) -> bytes:
        """Returns the Reed-Solomon error correction codeword for the given data and divisor polynomials."""
        result = bytearray([0] * len(divisor))
        for b in data:  # Polynomial division
            factor: int = b ^ result.pop(0)
            result.append(0)
            for (i, coef) in enumerate(divisor):
                result[i] ^= QrCode._reed_solomon_multiply(coef, factor)
        return result
    
    
    @staticmethod
    def _reed_solomon_multiply(x: int, y: int) -> int:
        """Returns the product of the two given field elements modulo GF(2^8/0x11D). The arguments and result
        are unsigned 8-bit integers. This could be implemented as a lookup table of 256*256 entries of uint8."""
        if (x >> 8 != 0) or (y >> 8 != 0):
            raise ValueError("Byte out of range")
        # Russian peasant multiplication
        z: int = 0
        for i in reversed(range(8)):
            z = (z << 1) ^ ((z >> 7) * 0x11D)
            z ^= ((y >> i) & 1) * x
        assert z >> 8 == 0
        return z
    
    
    def _finder_penalty_count_patterns(self, runhistory: collections.deque[int]) -> int:
        """Can only be called immediately after a light run is added, and
        returns either 0, 1, or 2. A helper function for _get_penalty_score()."""
        n: int = runhistory[1]
        assert n <= self._size * 3
        core: bool = n > 0 and (runhistory[2] == runhistory[4] == runhistory[5] == n) and runhistory[3] == n * 3
        return (1 if (core and runhistory[0] >= n * 4 and runhistory[6] >= n) else 0) \
             + (1 if (core and runhistory[6] >= n * 4 and runhistory[0] >= n) else 0)
    
    
    def _finder_penalty_terminate_and_count(self, currentruncolor: bool, currentrunlength: int, runhistory: collections.deque[int]) -> int:
        """Must be called at the end of a line (row or column) of modules. A helper function for _get_penalty_score()."""
        if currentruncolor:  # Terminate dark run
            self._finder_penalty_add_history(currentrunlength, runhistory)
            currentrunlength = 0
        currentrunlength += self._size  # Add light border to final run
        self._finder_penalty_add_history(currentrunlength, runhistory)
        return self._finder_penalty_count_patterns(runhistory)
    
    
    def _finder_penalty_add_history(self, currentrunlength: int, runhistory: collections.deque[int]) -> None:
        if runhistory[0] == 0:
            currentrunlength += self._size  # Add light border to initial run
        runhistory.appendleft(currentrunlength)
    
    
    # ---- Constants and tables ----
    
    MIN_VERSION: int =  1  # The minimum version number supported in the QR Code Model 2 standard
    MAX_VERSION: int = 40  # The maximum version number supported in the QR Code Model 2 standard
    
    # For use in _get_penalty_score(), when evaluating which mask is best.
    _PENALTY_N1: int =  3
    _PENALTY_N2: int =  3
    _PENALTY_N3: int = 40
    _PENALTY_N4: int = 10
    
    _ECC_CODEWORDS_PER_BLOCK: Sequence[Sequence[int]] = (
        # Version: (note that index 0 is for padding, and is set to an illegal value)
        # 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
        (-1,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),  # Low
        (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),  # Medium
        (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),  # Quartile
        (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30))  # High
    
    _NUM_ERROR_CORRECTION_BLOCKS: Sequence[Sequence[int]] = (
        # Version: (note that index 0 is for padding, and is set to an illegal value)
        # 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
        (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4,  4,  4,  4,  4,  6,  6,  6,  6,  7,  8,  8,  9,  9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),  # Low
        (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5,  5,  8,  9,  9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),  # Medium
        (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8,  8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),  # Quartile
        (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81))  # High
    
    _MASK_PATTERNS: Sequence[collections.abc.Callable[[int,int],int]] = (
        (lambda x, y:  (x + y) % 2                  ),
        (lambda x, y:  y % 2                        ),
        (lambda x, y:  x % 3                        ),
        (lambda x, y:  (x + y) % 3                  ),
        (lambda x, y:  (x // 3 + y // 2) % 2        ),
        (lambda x, y:  x * y % 2 + x * y % 3        ),
        (lambda x, y:  (x * y % 2 + x * y % 3) % 2  ),
        (lambda x, y:  ((x + y) % 2 + x * y % 3) % 2),
    )
    
    
    # ---- Public helper enumeration ----
    
    class Ecc:
        ordinal: int  # (Public) In the range 0 to 3 (unsigned 2-bit integer)
        formatbits: int  # (Package-private) In the range 0 to 3 (unsigned 2-bit integer)
        
        """The error correction level in a QR Code symbol. Immutable."""
        # Private constructor
        def __init__(self, i: int, fb: int) -> None:
            self.ordinal = i
            self.formatbits = fb
        
        # Placeholders
        LOW     : QrCode.Ecc
        MEDIUM  : QrCode.Ecc
        QUARTILE: QrCode.Ecc
        HIGH    : QrCode.Ecc
    
    # Public constants. Create them outside the class.
    Ecc.LOW      = Ecc(0, 1)  # The QR Code can tolerate about  7% erroneous codewords
    Ecc.MEDIUM   = Ecc(1, 0)  # The QR Code can tolerate about 15% erroneous codewords
    Ecc.QUARTILE = Ecc(2, 3)  # The QR Code can tolerate about 25% erroneous codewords
    Ecc.HIGH     = Ecc(3, 2)  # The QR Code can tolerate about 30% erroneous codewords



# ---- Data segment class ----

class QrSegment:
    """A segment of character/binary/control data in a QR Code symbol.
    Instances of this class are immutable.
    The mid-level way to create a segment is to take the payload data
    and call a static factory function such as QrSegment.make_numeric().
    The low-level way to create a segment is to custom-make the bit buffer
    and call the QrSegment() constructor with appropriate values.
    This segment class imposes no length restrictions, but QR Codes have restrictions.
    Even in the most favorable conditions, a QR Code can only hold 7089 characters of data.
    Any segment longer than this is meaningless for the purpose of generating QR Codes."""
    
    # ---- Static factory functions (mid level) ----
    
    @staticmethod
    def make_bytes(data: Union[bytes,Sequence[int]]) -> QrSegment:
        """Returns a segment representing the given binary data encoded in byte mode.
        All input byte lists are acceptable. Any text string can be converted to
        UTF-8 bytes (s.encode("UTF-8")) and encoded as a byte mode segment."""
        bb = _BitBuffer()
        for b in data:
            bb.append_bits(b, 8)
        return QrSegment(QrSegment.Mode.BYTE, len(data), bb)
    
    
    @staticmethod
    def make_numeric(digits: str) -> QrSegment:
        """Returns a segment representing the given string of decimal digits encoded in numeric mode."""
        if not QrSegment.is_numeric(digits):
            raise ValueError("String contains non-numeric characters")
        bb = _BitBuffer()
        i: int = 0
        while i < len(digits):  # Consume up to 3 digits per iteration
            n: int = min(len(digits) - i, 3)
            bb.append_bits(int(digits[i : i + n]), n * 3 + 1)
            i += n
        return QrSegment(QrSegment.Mode.NUMERIC, len(digits), bb)
    
    
    @staticmethod
    def make_alphanumeric(text: str) -> QrSegment:
        """Returns a segment representing the given text string encoded in alphanumeric mode.
        The characters allowed are: 0 to 9, A to Z (uppercase only), space,
        dollar, percent, asterisk, plus, hyphen, period, slash, colon."""
        if not QrSegment.is_alphanumeric(text):
            raise ValueError("String contains unencodable characters in alphanumeric mode")
        bb = _BitBuffer()
        for i in range(0, len(text) - 1, 2):  # Process groups of 2
            temp: int = QrSegment._ALPHANUMERIC_ENCODING_TABLE[text[i]] * 45
            temp += QrSegment._ALPHANUMERIC_ENCODING_TABLE[text[i + 1]]
            bb.append_bits(temp, 11)
        if len(text) % 2 > 0:  # 1 character remaining
            bb.append_bits(QrSegment._ALPHANUMERIC_ENCODING_TABLE[text[-1]], 6)
        return QrSegment(QrSegment.Mode.ALPHANUMERIC, len(text), bb)
    
    
    @staticmethod
    def make_segments(text: str) -> list[QrSegment]:
        """Returns a new mutable list of zero or more segments to represent the given Unicode text string.
        The result may use various segment modes and switch modes to optimize the length of the bit stream."""
        
        # Select the most efficient segment encoding automatically
        if text == "":
            return []
        elif QrSegment.is_numeric(text):
            return [QrSegment.make_numeric(text)]
        elif QrSegment.is_alphanumeric(text):
            return [QrSegment.make_alphanumeric(text)]
        else:
            return [QrSegment.make_bytes(text.encode("UTF-8"))]
    
    
    @staticmethod
    def make_eci(assignval: int) -> QrSegment:
        """Returns a segment representing an Extended Channel Interpretation
        (ECI) designator with the given assignment value."""
        bb = _BitBuffer()
        if assignval < 0:
            raise ValueError("ECI assignment value out of range")
        elif assignval < (1 << 7):
            bb.append_bits(assignval, 8)
        elif assignval < (1 << 14):
            bb.append_bits(0b10, 2)
            bb.append_bits(assignval, 14)
        elif assignval < 1000000:
            bb.append_bits(0b110, 3)
            bb.append_bits(assignval, 21)
        else:
            raise ValueError("ECI assignment value out of range")
        return QrSegment(QrSegment.Mode.ECI, 0, bb)
    
    
    # Tests whether the given string can be encoded as a segment in numeric mode.
    # A string is encodable iff each character is in the range 0 to 9.
    @staticmethod
    def is_numeric(text: str) -> bool:
        return QrSegment._NUMERIC_REGEX.fullmatch(text) is not None
    
    
    # Tests whether the given string can be encoded as a segment in alphanumeric mode.
    # A string is encodable iff each character is in the following set: 0 to 9, A to Z
    # (uppercase only), space, dollar, percent, asterisk, plus, hyphen, period, slash, colon.
    @staticmethod
    def is_alphanumeric(text: str) -> bool:
        return QrSegment._ALPHANUMERIC_REGEX.fullmatch(text) is not None
    
    
    # ---- Private fields ----
    
    # The mode indicator of this segment. Accessed through get_mode().
    _mode: QrSegment.Mode
    
    # The length of this segment's unencoded data. Measured in characters for
    # numeric/alphanumeric/kanji mode, bytes for byte mode, and 0 for ECI mode.
    # Always zero or positive. Not the same as the data's bit length.
    # Accessed through get_num_chars().
    _numchars: int
    
    # The data bits of this segment. Accessed through get_data().
    _bitdata: list[int]
    
    
    # ---- Constructor (low level) ----
    
    def __init__(self, mode: QrSegment.Mode, numch: int, bitdata: Sequence[int]) -> None:
        """Creates a new QR Code segment with the given attributes and data.
        The character count (numch) must agree with the mode and the bit buffer length,
        but the constraint isn't checked. The given bit buffer is cloned and stored."""
        if numch < 0:
            raise ValueError()
        self._mode = mode
        self._numchars = numch
        self._bitdata = list(bitdata)  # Make defensive copy
    
    
    # ---- Accessor methods ----
    
    def get_mode(self) -> QrSegment.Mode:
        """Returns the mode field of this segment."""
        return self._mode
    
    def get_num_chars(self) -> int:
        """Returns the character count field of this segment."""
        return self._numchars
    
    def get_data(self) -> list[int]:
        """Returns a new copy of the data bits of this segment."""
        return list(self._bitdata)  # Make defensive copy
    
    
    # Package-private function
    @staticmethod
    def get_total_bits(segs: Sequence[QrSegment], version: int) -> Optional[int]:
        """Calculates the number of bits needed to encode the given segments at
        the given version. Returns a non-negative number if successful. Otherwise
        returns None if a segment has too many characters to fit its length field."""
        result = 0
        for seg in segs:
            ccbits: int = seg.get_mode().num_char_count_bits(version)
            if seg.get_num_chars() >= (1 << ccbits):
                return None  # The segment's length doesn't fit the field's bit width
            result += 4 + ccbits + len(seg._bitdata)
        return result
    
    
    # ---- Constants ----
    
    # Describes precisely all strings that are encodable in numeric mode.
    _NUMERIC_REGEX: re.Pattern[str] = re.compile(r"[0-9]*")
    
    # Describes precisely all strings that are encodable in alphanumeric mode.
    _ALPHANUMERIC_REGEX: re.Pattern[str] = re.compile(r"[A-Z0-9 $%*+./:-]*")
    
    # Dictionary of "0"->0, "A"->10, "$"->37, etc.
    _ALPHANUMERIC_ENCODING_TABLE: dict[str,int] = {ch: i for (i, ch) in enumerate("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")}
    
    
    # ---- Public helper enumeration ----
    
    class Mode:
        """Describes how a segment's data bits are interpreted. Immutable."""
        
        _modebits: int  # The mode indicator bits, which is a uint4 value (range 0 to 15)
        _charcounts: tuple[int,int,int]  # Number of character count bits for three different version ranges
        
        # Private constructor
        def __init__(self, modebits: int, charcounts: tuple[int,int,int]):
            self._modebits = modebits
            self._charcounts = charcounts
        
        # Package-private method
        def get_mode_bits(self) -> int:
            """Returns an unsigned 4-bit integer value (range 0 to 15) representing the mode indicator bits for this mode object."""
            return self._modebits
        
        # Package-private method
        def num_char_count_bits(self, ver: int) -> int:
            """Returns the bit width of the character count field for a segment in this mode
            in a QR Code at the given version number. The result is in the range [0, 16]."""
            return self._charcounts[(ver + 7) // 17]
        
        # Placeholders
        NUMERIC     : QrSegment.Mode
        ALPHANUMERIC: QrSegment.Mode
        BYTE        : QrSegment.Mode
        KANJI       : QrSegment.Mode
        ECI         : QrSegment.Mode
    
    # Public constants. Create them outside the class.
    Mode.NUMERIC      = Mode(0x1, (10, 12, 14))
    Mode.ALPHANUMERIC = Mode(0x2, ( 9, 11, 13))
    Mode.BYTE         = Mode(0x4, ( 8, 16, 16))
    Mode.KANJI        = Mode(0x8, ( 8, 10, 12))
    Mode.ECI          = Mode(0x7, ( 0,  0,  0))



# ---- Private helper class ----

class _BitBuffer(list[int]):
    """An appendable sequence of bits (0s and 1s). Mainly used by QrSegment."""
    
    def append_bits(self, val: int, n: int) -> None:
        """Appends the given number of low-order bits of the given
        value to this buffer. Requires n >= 0 and 0 <= val < 2^n."""
        if (n < 0) or (val >> n != 0):
            raise ValueError("Value out of range")
        self.extend(((val >> i) & 1) for i in reversed(range(n)))


def _get_bit(x: int, i: int) -> bool:
    """Returns true iff the i'th bit of x is set to 1."""
    return (x >> i) & 1 != 0



class DataTooLongError(ValueError):
    """Raised when the supplied data does not fit any QR Code version. Ways to handle this exception include:
    - Decrease the error correction level if it was greater than Ecc.LOW.
    - If the encode_segments() function was called with a maxversion argument, then increase
      it if it was less than QrCode.MAX_VERSION. (This advice does not apply to the other
      factory functions because they search all versions up to QrCode.MAX_VERSION.)
    - Split the text data into better or optimal segments in order to reduce the number of bits required.
    - Change the text or binary data to be shorter.
    - Change the text to fit the character set of a particular segment mode (e.g. alphanumeric).
    - Propagate the error upward to the caller/user."""
    pass


def make_qr_png_bytes(display_url):
    """QR code PNG for the ss link, or None on failure.

    Uses the embedded Nayuki qrcodegen (above, stdlib-only, MIT)
    for the matrix, then renders the PNG with stdlib zlib.
    Pillow's make_image is deliberately NOT used: on a VPS
    without Pillow it crashes even when a QR library is present.
    A failure here never breaks the key post — the caller
    falls back to a text post with the Buy buttons."""
    try:
        import binascii
        import struct
        import zlib
        qr = QrCode.encode_text(display_url, QrCode.Ecc.MEDIUM)
        modules = qr.get_size()
        matrix = [[qr.get_module(x, y) for x in range(modules)]
                  for y in range(modules)]
        box = 10
        border = 4
        modules = len(matrix)
        size = (modules + 2 * border) * box
        raw = bytearray()
        for y in range(size):
            raw.append(0)
            my = y // box - border
            for x in range(size):
                mx = x // box - border
                dark = 0 <= my < modules and 0 <= mx < modules and bool(matrix[my][mx])
                raw.append(0 if dark else 255)
        def chunk(kind, data):
            c = struct.pack(">I", len(data)) + kind + data
            return c + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
        png = b"\x89PNG\r\n\x1a\n"
        png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0))
        png += chunk(b"IDAT", zlib.compress(bytes(raw)))
        png += chunk(b"IEND", b"")
        return png
    except Exception as e:
        log(f"WARNING: QR generation failed, posting text only: {e}")
        return None


def tg_send_photo(cfg, caption, qr_bytes):
    """sendPhoto via multipart upload (Bot API does not accept a
    photo file as JSON). reply_markup is a JSON string in multipart."""
    import urllib.error
    boundary = "----kshchannelbot" + os.urandom(16).hex()
    body = bytearray()

    def field(name, value):
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")

    field("chat_id", str(cfg["channel_id"]))
    field("caption", caption)
    field("parse_mode", "HTML")
    field("reply_markup", json.dumps(buy_keyboard()))
    body.extend(f"--{boundary}\r\n".encode())
    body.extend(b'Content-Disposition: form-data; name="photo"; filename="key_qr.png"\r\n')
    body.extend(b"Content-Type: image/png\r\n\r\n")
    body.extend(qr_bytes)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    url = f"https://api.telegram.org/bot{cfg['bot_token']}/sendPhoto"
    req = urllib.request.Request(url, data=bytes(body), method="POST", headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Telegram HTTP {e.code}: {detail}")


def delete_channel_message(cfg, message_id):
    """Best-effort delete of a previous channel post. Never raises —
    a manually deleted post must not break the new post."""
    if not message_id:
        return False
    try:
        res = tg_request(cfg, "deleteMessage", {
            "chat_id": cfg["channel_id"],
            "message_id": int(message_id),
        })
        return bool(res.get("ok"))
    except Exception as e:
        log(f"WARNING: old channel post delete failed (ignored): {e}")
        return False


def edit_post_usage(cfg, used_bytes):
    """Edit the latest channel post with a fresh usage bar.
    Preserves the Buy buttons (edit without reply_markup would
    drop them). Returns True on success."""
    msg_id = cfg.get("last_channel_message_id", "")
    if not msg_id:
        return False
    display_url = cfg.get("last_post_display_url", "")
    key_name = cfg.get("last_post_key_name", "") or cfg.get("current_key_name", "")
    if not display_url:
        return False
    last_post = cfg.get("last_post_iso", "")
    post_myanmar = None
    if last_post:
        try:
            post_myanmar = datetime.fromisoformat(last_post.replace("Z", "+00:00")).astimezone(MYANMAR_TZ).strftime("%Y-%m-%d %H:%M")
        except Exception:
            post_myanmar = None
    text = build_post_text(cfg, display_url, key_name, used_bytes=used_bytes, post_myanmar=post_myanmar)
    try:
        if cfg.get("last_channel_message_type", "text") == "photo":
            res = tg_request(cfg, "editMessageCaption", {
                "chat_id": cfg["channel_id"],
                "message_id": int(msg_id),
                "caption": text,
                "parse_mode": "HTML",
                "reply_markup": buy_keyboard(),
            })
        else:
            res = tg_request(cfg, "editMessageText", {
                "chat_id": cfg["channel_id"],
                "message_id": int(msg_id),
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
                "reply_markup": buy_keyboard(),
            })
        return bool(res.get("ok"))
    except Exception as e:
        log(f"WARNING: usage-bar edit failed (ignored): {e}")
        return False


def post_key_to_channel(cfg, access_url, key_name=""):
    """Post a key to the channel. Returns (message_id, message_type).

    Preferred: QR photo + caption + Buy buttons. Fallbacks,
    in order, so a QR/formatting failure never loses the key post:
    QR photo fails -> text post with code block + Buy buttons.
    On success, the previous channel post is deleted best-effort
    (so only the latest working key stays visible) and the new
    message id/type/display link are stored for usage-bar edits.
    Caption limit is 1024 chars — the v1.4 post is kept well under
    it; if Telegram ever rejects the photo caption, the text
    fallback (4096 chars) still posts the key."""
    display_url = display_access_url(cfg, access_url, key_name)
    text = build_post_text(cfg, display_url, key_name, used_bytes=0)
    old_msg_id = cfg.get("last_channel_message_id", "")
    msg_id = None
    msg_type = "text"
    qr_bytes = make_qr_png_bytes(display_url)
    if qr_bytes:
        try:
            res = tg_send_photo(cfg, text, qr_bytes)
            if res.get("ok"):
                msg_id = res.get("result", {}).get("message_id")
                msg_type = "photo"
            else:
                log(f"WARNING: sendPhoto not ok, falling back to text: {res}")
        except Exception as e:
            log(f"WARNING: sendPhoto failed, falling back to text: {e}")
    if msg_id is None:
        res = tg_request(cfg, "sendMessage", {
            "chat_id": cfg["channel_id"],
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "reply_markup": buy_keyboard(),
        })
        if not res.get("ok"):
            raise RuntimeError(f"Telegram send failed: {res}")
        msg_id = res.get("result", {}).get("message_id")
        msg_type = "text"
    if old_msg_id and str(old_msg_id) != str(msg_id):
        delete_channel_message(cfg, old_msg_id)
    cfg["last_channel_message_id"] = msg_id
    cfg["last_channel_message_type"] = msg_type
    cfg["last_post_display_url"] = display_url
    cfg["last_post_key_name"] = key_name
    cfg["last_usage_percent"] = 0
    cfg["last_usage_edit_iso"] = ""
    save_config(cfg)
    return msg_id, msg_type


def publish_pending(cfg):
    """Try to post the pending key; on success adopt it. Returns True if done."""
    new_id = cfg.get("pending_new_key_id", "")
    new_url = cfg.get("pending_new_access_url", "")
    if not new_id or not new_url:
        return False
    new_name = cfg.get("pending_new_key_name", "")
    log(f"retrying pending key {mask_key(new_id)} post")
    post_key_to_channel(cfg, new_url, new_name)
    old = cfg.get("current_key_id", "")
    cfg["current_key_id"] = new_id
    cfg["current_key_name"] = new_name
    cfg["pending_new_key_id"] = ""
    cfg["pending_new_access_url"] = ""
    cfg["pending_new_key_name"] = ""
    cfg["last_post_iso"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    save_config(cfg)
    delete_key(cfg, old)
    log(f"pending key posted and adopted: {mask_key(new_id)}")
    return True


def handle_admin_commands(cfg):
    """Best-effort admin commands via getUpdates (admin id only).

    /status -> reply to admin with current state (no secrets).
    /postnow -> force a new key + post now, bypassing the 24h wait
                 (manual test / admin action only, never automatic).
    /stop   -> disable the timer (admin restarts via the app Start).
    Command failures never fail the main check.
    """
    try:
        res = tg_request(cfg, "getUpdates", {
            "offset": int(cfg.get("tg_offset", 0) or 0),
            "timeout": 0,
            "allowed_updates": ["message"],
        })
    except Exception as e:
        log(f"WARNING: getUpdates failed (commands skipped): {e}")
        return
    if not res.get("ok"):
        return
    admin_id = str(cfg.get("admin_id", ""))
    for upd in res.get("result", []):
        cfg["tg_offset"] = int(upd.get("update_id", 0)) + 1
        msg = upd.get("message", {}) or {}
        sender = str((msg.get("from") or {}).get("id", ""))
        text = (msg.get("text") or "").strip()
        chat_id = msg.get("chat", {}).get("id")
        if sender != admin_id or not text.startswith("/"):
            continue
        cmd = text.split()[0].split("@")[0]
        try:
            if cmd == "/status":
                last = cfg.get("last_post_iso", "")
                reply = (
                    "KSH Channel Bot status\n"
                    f"Current key: {'yes' if cfg.get('current_key_id') else 'no'}\n"
                    f"Pending key: {'yes' if cfg.get('pending_new_key_id') else 'no'}\n"
                    f"Last post (UTC): {last or '-'}"
                )
                tg_request(cfg, "sendMessage", {"chat_id": chat_id, "text": reply})
            elif cmd == "/postnow":
                old = cfg.get("current_key_id", "")
                new_id, new_url, new_name = create_new_key(cfg)
                post_key_to_channel(cfg, new_url, new_name)
                cfg["current_key_id"] = new_id
                cfg["current_key_name"] = new_name
                cfg["last_post_iso"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                save_config(cfg)
                delete_key(cfg, old)
                tg_request(cfg, "sendMessage", {
                    "chat_id": chat_id,
                    "text": f"Posted a new key now: {mask_key(new_id)}",
                })
            elif cmd == "/stop":
                tg_request(cfg, "sendMessage", {
                    "chat_id": chat_id,
                    "text": "Stopping the channel bot timer. Restart from the app Start button.",
                })
                os.system(f"systemctl disable --now {SERVICE_TIMER} >/dev/null 2>&1")
        except Exception as e:
            log(f"WARNING: admin command {cmd} failed: {e}")
    save_config(cfg)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-once", action="store_true",
                        help="Timer mode: check usage, post only when due (default).")
    parser.add_argument("--rotate-now", action="store_true",
                        help="Manual test only: force a new key + post now, bypassing the 24h wait.")
    parser.add_argument("--report-only", action="store_true",
                        help="Install test: report that Outline + config work, create no key.")
    args = parser.parse_args()
    try:
        lock = BotLock()
        lock.__enter__()
    except BlockingIOError:
        log("another bot run is already active — exiting, no duplicate key")
        return 0
    try:
        return _main_locked(args)
    finally:
        lock.__exit__()


def _main_locked(args):
    cfg = load_config()
    # Refresh the pin at every run (disk cert if it matches live, else access.txt).
    # access.txt is never written by this bot.
    try:
        api_url, access_cert = parse_access_txt()
        cfg["api_url"] = api_url
        cfg["cert_sha256"] = resolve_cert_pin(api_url, access_cert)
        save_config(cfg)
    except Exception as e:
        log(f"WARNING: pin refresh failed, using stored pin: {e}")

    if args.report_only:
        # Install test: prove Outline API answers with the pinned cert.
        outline_request(cfg, "GET", "access-keys")
        write_status(cfg)
        log("report-only OK: Outline API reachable")
        qr_test = make_qr_png_bytes("ss://test@example.com:1234/?outline=1#test")
        log(f"QR test: {'OK' if qr_test else 'FAILED — posts will be text only'}")
        return 0

    # 0. Deleted-key detection: if the tracked current/pending key
    #    no longer exists in Outline (deleted manually in Manager/KSM),
    #    clear it so the bot posts a fresh key instead of waiting
    #    forever on a dead key (usage would stay 0). Only on a
    #    successful key-list fetch — a transient API failure must
    #    NOT clear tracking.
    try:
        keys_data = outline_request(cfg, "GET", "access-keys")
        live_ids = {k.get("id") for k in keys_data.get("accessKeys", [])}
        changed = False
        if cfg.get("current_key_id") and cfg["current_key_id"] not in live_ids:
            log(f"current key {mask_key(cfg['current_key_id'])} no longer in Outline — clearing, a fresh key will be posted")
            cfg["current_key_id"] = ""
            cfg["current_key_name"] = ""
            changed = True
        if cfg.get("pending_new_key_id") and cfg["pending_new_key_id"] not in live_ids:
            log(f"pending key {mask_key(cfg['pending_new_key_id'])} no longer in Outline — clearing pending")
            cfg["pending_new_key_id"] = ""
            cfg["pending_new_access_url"] = ""
            cfg["pending_new_key_name"] = ""
            changed = True
        if changed:
            save_config(cfg)
    except Exception as e:
        log(f"WARNING: key-list check failed, keeping tracked keys: {e}")

    # 1. Pending key first — never create a second orphan.
    if cfg.get("pending_new_key_id"):
        try:
            if publish_pending(cfg):
                write_status(cfg)
                handle_admin_commands(cfg)
                return 0
        except Exception as e:
            log(f"pending publish still failing: {e}")
            write_status(cfg, error=str(e)[:200])
            return 1

    current_key = cfg.get("current_key_id", "")
    if not current_key:
        log(f"no current key recorded — creating the first {limit_gb(cfg)} GB key")
        new_id, new_url, new_name = create_new_key(cfg)
        cfg["pending_new_key_id"] = new_id
        cfg["pending_new_access_url"] = new_url
        cfg["pending_new_key_name"] = new_name
        save_config(cfg)
        try:
            post_key_to_channel(cfg, new_url, new_name)
        except Exception as e:
            log(f"first post failed, key kept as pending: {e}")
            write_status(cfg, error=str(e)[:200])
            return 1
        cfg["current_key_id"] = new_id
        cfg["current_key_name"] = new_name
        cfg["pending_new_key_id"] = ""
        cfg["pending_new_access_url"] = ""
        cfg["pending_new_key_name"] = ""
        cfg["last_post_iso"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_config(cfg)
        log(f"first key posted: {mask_key(new_id)}")
        write_status(cfg)
        handle_admin_commands(cfg)
        return 0

    if args.rotate_now:
        log("rotate-now (manual test): forcing a new key + post, bypassing 24h wait")
        new_id, new_url, new_name = create_new_key(cfg)
        cfg["pending_new_key_id"] = new_id
        cfg["pending_new_access_url"] = new_url
        cfg["pending_new_key_name"] = new_name
        save_config(cfg)
        try:
            post_key_to_channel(cfg, new_url, new_name)
        except Exception as e:
            log(f"rotate-now post failed, key kept as pending: {e}")
            write_status(cfg, error=str(e)[:200])
            return 1
        old = current_key
        cfg["current_key_id"] = new_id
        cfg["current_key_name"] = new_name
        cfg["pending_new_key_id"] = ""
        cfg["pending_new_access_url"] = ""
        cfg["pending_new_key_name"] = ""
        cfg["last_post_iso"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_config(cfg)
        delete_key(cfg, old)
        log(f"rotate-now complete: new key {mask_key(new_id)} live")
        write_status(cfg)
        return 0

    # 2. Measure usage for the current key.
    metrics = outline_request(cfg, "GET", "metrics/transfer")
    by_user = {}
    if isinstance(metrics, dict):
        by_user = metrics.get("bytesTransferredByUserId") or {}
    usage = int(by_user.get(current_key, 0) or 0)
    log(f"key {mask_key(current_key)} usage {usage} bytes "
        f"({usage / 1024 ** 3:.2f} GiB, limit {limit_gb(cfg)} GB)")
    write_status(cfg)

    if usage < limit_bytes(cfg):
        try:
            percent = int((usage / limit_bytes(cfg)) * 100) if limit_bytes(cfg) > 0 else 0
            last_percent = int(cfg.get("last_usage_percent", 0) or 0)
            last_edit = cfg.get("last_usage_edit_iso", "")
            edit_due = False
            # v1.4.3 migration: bar style changed from used-green to
            # remaining-green. Force exactly one edit on the first run
            # with the old style so the CURRENT post flips immediately
            # instead of waiting for the next 10% step. The style is
            # only recorded after a successful edit (below), so a
            # failed edit retries on the next run. No rotation, no
            # post delete, no other config change.
            if cfg.get("usage_bar_style") != "remaining":
                edit_due = True
            if percent - last_percent >= 10:
                if not last_edit:
                    edit_due = True
                else:
                    try:
                        last_dt = datetime.fromisoformat(last_edit.replace("Z", "+00:00"))
                        edit_due = (datetime.now(timezone.utc) - last_dt).total_seconds() >= 3600
                    except Exception:
                        edit_due = True
            if edit_due and edit_post_usage(cfg, usage):
                cfg["last_usage_percent"] = percent
                cfg["last_usage_edit_iso"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                cfg["usage_bar_style"] = "remaining"
                save_config(cfg)
                log(f"usage bar updated to {percent}%")
        except Exception as e:
            log(f"WARNING: usage-bar update skipped: {e}")
        handle_admin_commands(cfg)
        return 0

    # 3. Exhausted: respect the 24h rule.
    last_post = cfg.get("last_post_iso", "")
    if last_post:
        try:
            last_dt = datetime.fromisoformat(last_post.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds()
            if elapsed < WAIT_SECONDS:
                remaining_h = (WAIT_SECONDS - elapsed) / 3600
                log(f"key exhausted but only {elapsed / 3600:.1f}h since last post "
                    f"— waiting {remaining_h:.1f}h more before posting")
                handle_admin_commands(cfg)
                return 0
        except Exception:
            pass
    log("key exhausted and 24h passed — creating a new key and posting it")
    new_id, new_url, new_name = create_new_key(cfg)
    cfg["pending_new_key_id"] = new_id
    cfg["pending_new_access_url"] = new_url
    cfg["pending_new_key_name"] = new_name
    save_config(cfg)
    try:
        post_key_to_channel(cfg, new_url, new_name)
    except Exception as e:
        log(f"post failed, new key kept as pending: {e}")
        write_status(cfg, error=str(e)[:200])
        return 1
    old = current_key
    cfg["current_key_id"] = new_id
    cfg["current_key_name"] = new_name
    cfg["pending_new_key_id"] = ""
    cfg["pending_new_access_url"] = ""
    cfg["pending_new_key_name"] = ""
    cfg["last_post_iso"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    save_config(cfg)
    delete_key(cfg, old)
    log(f"rotation complete: new key {mask_key(new_id)} live")
    write_status(cfg)
    handle_admin_commands(cfg)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)
