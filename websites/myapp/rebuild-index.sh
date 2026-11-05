#!/bin/bash
# rebuild-index.sh — regenerate /var/www/myapp/index.html from the APKs
# in /var/www/myapp/apks/ (name, size, date, download link).
# Idempotent: safe to run after every upload/delete. Env overrides:
#   APK_DIR — APK folder (default /var/www/myapp/apks)
#   OUTPUT  — index file to write (default /var/www/myapp/index.html)
set -euo pipefail

APK_DIR="${APK_DIR:-/var/www/myapp/apks}"
OUTPUT="${OUTPUT:-/var/www/myapp/index.html}"

python3 - "$APK_DIR" "$OUTPUT" <<'PYEOF'
import html
import os
import sys
import time

apk_dir, output = sys.argv[1], sys.argv[2]


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


try:
    names = [
        f
        for f in os.listdir(apk_dir)
        if f.endswith(".apk") and os.path.isfile(os.path.join(apk_dir, f))
    ]
except FileNotFoundError:
    names = []

names.sort(key=lambda f: os.path.getmtime(os.path.join(apk_dir, f)), reverse=True)

rows = []
for name in names:
    path = os.path.join(apk_dir, name)
    st = os.stat(path)
    date = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
    rows.append(
        '<tr><td>{}</td><td class="size">{}</td>'
        '<td class="date">{}</td><td>'
        '<a class="btn" href="apks/{}" download>Download</a></td></tr>'.format(
            html.escape(name),
            human(st.st_size),
            date,
            html.escape(name, quote=True),
        )
    )

body = "\n".join(rows) if rows else (
    '<tr><td colspan="4" class="empty">APK မရှိသေးဘူး။</td></tr>'
)

page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MyApp — APK Downloads</title>
<style>
  body { margin: 0; background: #0B1E3A; color: #fff; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
  .wrap { max-width: 760px; margin: 0 auto; padding: 32px 16px; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h1 span { color: #2DD4BF; }
  p.sub { color: #94A3B8; margin: 0 0 24px; }
  table { width: 100%; border-collapse: collapse; background: #16233D; border-radius: 12px; overflow: hidden; }
  th, td { padding: 12px 14px; text-align: left; font-size: 14px; }
  th { color: #2DD4BF; border-bottom: 1px solid #1E293B; }
  td { border-bottom: 1px solid #1E293B; word-break: break-all; }
  tr:last-child td { border-bottom: none; }
  .size, .date { color: #94A3B8; white-space: nowrap; }
  a.btn { display: inline-block; background: #2DD4BF; color: #000; text-decoration: none; font-weight: 700; padding: 8px 14px; border-radius: 8px; white-space: nowrap; }
  .empty { color: #94A3B8; text-align: center; }
  .foot { color: #64748B; font-size: 12px; margin-top: 20px; text-align: center; }
</style>
</head>
<body>
<div class="wrap">
  <h1>MyApp <span>APK Downloads</span></h1>
  <p class="sub">Tap Download to get the APK file.</p>
  <table>
    <thead>
      <tr><th>App</th><th>Size</th><th>Date</th><th></th></tr>
    </thead>
    <tbody>
__APK_ROWS__
    </tbody>
  </table>
  <p class="foot">Served by MyApp — managed with Bot Manager.</p>
</div>
</body>
</html>
"""

with open(output, "w", encoding="utf-8") as f:
    f.write(page.replace("__APK_ROWS__", body))

print(f"index.html rebuilt: {len(names)} APK(s)")
PYEOF
