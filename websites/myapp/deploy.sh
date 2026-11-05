#!/bin/bash
# deploy.sh — MyApp website deploy, run by the Bot Manager app (Website tab).
# Usage: bash deploy.sh <domain>
#   Domain must already point at this VPS (DNS is changed by hand in
#   Cloudflare) and port 80 must be free, otherwise certbot cannot
#   issue a certificate and this script stops with CERT FAILED.
# Idempotent / re-runnable: a VPS change is just Deploy again on the
# new VPS after DNS points at it. Existing APKs in /var/www/myapp/apks/
# are never touched.
set -u

DOMAIN="${1:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_ROOT="/var/www/myapp"
APK_DIR="$WEB_ROOT/apks"
NGINX_AVAIL="/etc/nginx/sites-available/myapp"
REBUILD_BIN="/usr/local/bin/myapp-rebuild-index.sh"

log() { echo "[myapp] $*"; }

if ! [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
  log "DOMAIN မမှန်ဘူး: $DOMAIN"
  exit 1
fi

# 1. nginx + certbot (only if missing).
if ! command -v nginx >/dev/null 2>&1 || ! command -v certbot >/dev/null 2>&1; then
  log "nginx / certbot သွင်းနေသည်..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq nginx certbot || {
    log "INSTALL FAILED: nginx / certbot သွင်းလို့ မရဘူး"
    exit 1
  }
fi
log "nginx + certbot OK"

# 2. Web root + APK folder (APKs already there are kept).
mkdir -p "$APK_DIR"

# 3. Install the rebuild script.
cp "$DIR/rebuild-index.sh" "$REBUILD_BIN"
chmod 755 "$REBUILD_BIN"
log "rebuild script OK"

# 4. HTTP-only vhost first, so certbot webroot can answer the challenge.
cat > "$NGINX_AVAIL" <<'VHOST'
server {
    listen 80;
    server_name __DOMAIN__;

    root /var/www/myapp;
    index index.html;

    location /.well-known/acme-challenge/ {
        root /var/www/myapp;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
VHOST
sed -i "s/__DOMAIN__/$DOMAIN/g" "$NGINX_AVAIL"
ln -sf "$NGINX_AVAIL" /etc/nginx/sites-enabled/myapp
nginx -t || { log "NGINX CONFIG FAILED"; exit 1; }
systemctl enable nginx >/dev/null 2>&1 || true
systemctl reload nginx 2>/dev/null || systemctl restart nginx
log "HTTP site OK: http://$DOMAIN"

# 5. Rebuild the download page from the APKs on disk.
"$REBUILD_BIN"

# 6. Firewall: open 80/443 when ufw is active (best-effort, never fatal).
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
fi

# 7. SSL certificate (webroot — never standalone, port 80 stays with nginx).
if ! certbot certonly --webroot -w "$WEB_ROOT" -d "$DOMAIN" \
    --non-interactive --agree-tos --register-unsafely-without-email \
    --keep-until-expiring >/tmp/myapp-certbot.log 2>&1; then
  log "CERT FAILED: certbot cert ထုတ်လို့ မရဘူး"
  log "DNS က ဒီ VPS IP ကို ညွှန်ပြီးပြီလား, port 80 လွတ်လား စစ်ပါ"
  log "HTTP site ကတော့ အလုပ်လုပ်နေတယ်: http://$DOMAIN"
  exit 1
fi
log "cert OK"

# 8. Final vhost (HTTP -> HTTPS redirect + HTTPS site), then reload.
sed "s/__DOMAIN__/$DOMAIN/g" "$DIR/myapp.nginx" > "$NGINX_AVAIL"
nginx -t || { log "NGINX CONFIG FAILED"; exit 1; }
systemctl reload nginx 2>/dev/null || systemctl restart nginx
log "HTTPS vhost OK"

# 9. Verify the live site answers 200 over HTTPS.
CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://$DOMAIN/" || echo 000)"
if [ "$CODE" != "200" ]; then
  log "VERIFY FAILED: https://$DOMAIN/ returned $CODE"
  exit 1
fi
log "SITE OK: https://$DOMAIN/ (200)"
log "DEPLOY OK"
