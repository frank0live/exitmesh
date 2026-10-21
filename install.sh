#!/usr/bin/env bash
# ExitMesh installer — one file, idempotent, systemd-native.
#
#   bash <(curl -Ls https://raw.githubusercontent.com/frank0live/exitmesh/main/install.sh)
#
# Sub-commands:  install | update | uninstall | status | panel-url | set-password
set -uo pipefail

APP="exitmesh"
PREFIX="${EXITMESH_PREFIX:-/opt/exitmesh}"
STATE="${EXITMESH_STATE:-/var/lib/exitmesh}"
CONF="${EXITMESH_CONF:-/etc/exitmesh}"
XRAY_DIR="${EXITMESH_XRAY_DIR:-/usr/local/bin/xray-bin}"
REPO="${EXITMESH_REPO:-https://github.com/frank0live/exitmesh.git}"
BRANCH="${EXITMESH_BRANCH:-main}"
SVC_PANEL="exitmesh-panel"

C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_WARN=$'\033[33m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s▸%s %s\n' "$C_DIM" "$C_OFF" "$*"; }
ok()   { printf '  %s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
die()  { printf '  %s✗%s %s\n' "$C_BAD" "$C_OFF" "$*" >&2; exit 1; }

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (sudo -i)"; }

pkg() {
  if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1
  elif command -v dnf >/dev/null; then dnf install -y -q "$@" >/dev/null 2>&1
  elif command -v pacman >/dev/null; then pacman -S --noconfirm --needed "$@" >/dev/null 2>&1
  fi
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "64" ;;
    aarch64|arm64) echo "arm64-v8a" ;;
    armv7l|armv7) echo "arm32-v7a" ;;
    *) echo "" ;;
  esac
}

# ---------------------------------------------------------------- dependencies
ensure_python() {
  if command -v python3 >/dev/null && python3 -c 'import sys;sys.exit(0 if sys.version_info>=(3,9) else 1)'; then
    ok "python $(python3 -V 2>&1 | awk '{print $2}')"; return
  fi
  step "installing python3"
  pkg python3 || die "could not install python3"
  ok "python3 installed"
}

ensure_xray() {
  if [[ -x "$XRAY_DIR/xray" ]]; then
    ok "xray $("$XRAY_DIR/xray" version 2>/dev/null | head -1 | awk '{print $2}')"
    return
  fi
  local a; a="$(arch)"
  [[ -n "$a" ]] || die "unsupported architecture: $(uname -m)"

  step "fetching xray-core ($a)"
  local url tmp
  url=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null \
        | grep -o "https://[^\"]*Xray-linux-$a.zip" | head -1)
  [[ -n "$url" ]] || die "could not resolve the xray release URL (no network?)"

  tmp=$(mktemp -d)
  if ! curl -fsSL --retry 3 -o "$tmp/x.zip" "$url"; then
    rm -rf "$tmp"; die "download failed: $url"
  fi
  if command -v unzip >/dev/null; then unzip -qo "$tmp/x.zip" -d "$tmp"
  else python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$tmp/x.zip" "$tmp"
  fi
  [[ -f "$tmp/xray" ]] || { rm -rf "$tmp"; die "xray binary missing from archive"; }

  install -d -m 755 "$XRAY_DIR"
  install -m 755 "$tmp/xray" "$XRAY_DIR/xray"
  [[ -f "$tmp/geoip.dat" ]] && install -m 644 "$tmp/geoip.dat" "$XRAY_DIR/geoip.dat"
  [[ -f "$tmp/geosite.dat" ]] && install -m 644 "$tmp/geosite.dat" "$XRAY_DIR/geosite.dat"
  rm -rf "$tmp"
  ok "xray installed at $XRAY_DIR/xray"
}

# ------------------------------------------------------------------- source
fetch_source() {
  step "installing application files"
  install -d -m 755 "$PREFIX" "$STATE" "$CONF" "$CONF/xray"

  if [[ -n "${EXITMESH_SRC:-}" && -d "${EXITMESH_SRC}" ]]; then
    cp -a "$EXITMESH_SRC/exitmesh" "$PREFIX/" 2>/dev/null
    cp -a "$EXITMESH_SRC/web" "$PREFIX/" 2>/dev/null
    cp -a "$EXITMESH_SRC/tests" "$PREFIX/" 2>/dev/null
    ok "copied from $EXITMESH_SRC"
  else
    command -v git >/dev/null || pkg git
    local tmp; tmp=$(mktemp -d)
    if git clone -q --depth 1 -b "$BRANCH" "$REPO" "$tmp/src" 2>/dev/null; then
      cp -a "$tmp/src/exitmesh" "$PREFIX/"
      cp -a "$tmp/src/web" "$PREFIX/"
      cp -a "$tmp/src/tests" "$PREFIX/"
      rm -rf "$tmp"
      ok "cloned $REPO"
    else
      rm -rf "$tmp"
      die "git clone failed — set EXITMESH_SRC=/path/to/checkout to install from disk"
    fi
  fi

  cat > "$PREFIX/run-panel.py" <<PY
#!/usr/bin/env python3
import os, sys
sys.path.insert(0, "$PREFIX")
from exitmesh.panel import serve

serve(
    db_path=os.environ.get("EXITMESH_DB", "$STATE/exitmesh.db"),
    xray_bin=os.environ.get("EXITMESH_XRAY", "$XRAY_DIR/xray"),
    listen=os.environ.get("EXITMESH_LISTEN", "127.0.0.1"),
    port=int(os.environ.get("EXITMESH_PORT", "0")) or None,
)
PY
  chmod +x "$PREFIX/run-panel.py"

  cat > /usr/local/bin/exitmesh <<SH
#!/usr/bin/env bash
exec python3 "$PREFIX/exitmesh/cli.py" "\$@"
SH
  chmod +x /usr/local/bin/exitmesh
  ok "cli installed at /usr/local/bin/exitmesh"
}

# ------------------------------------------------------------------ systemd
write_units() {
  step "writing systemd units"
  local port="${PANEL_PORT:-8099}"
  local listen="${PANEL_LISTEN:-127.0.0.1}"

  cat > "/etc/systemd/system/$SVC_PANEL.service" <<EOF
[Unit]
Description=ExitMesh panel and SOCKS router
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=EXITMESH_DB=$STATE/exitmesh.db
Environment=EXITMESH_XRAY=$XRAY_DIR/xray
Environment=EXITMESH_LISTEN=$listen
Environment=EXITMESH_PORT=$port
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 $PREFIX/run-panel.py
Restart=always
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=$STATE $CONF /tmp

[Install]
WantedBy=multi-user.target
EOF

  if [[ "${EXITMESH_NO_SYSTEMD:-0}" == "1" ]]; then
    warn "EXITMESH_NO_SYSTEMD=1 — unit written but not enabled"
    return
  fi
  systemctl daemon-reload
  systemctl enable --now "$SVC_PANEL" >/dev/null 2>&1
  sleep 2
  if systemctl is-active --quiet "$SVC_PANEL"; then
    ok "$SVC_PANEL active on $listen:$port"
  else
    warn "$SVC_PANEL failed to start"
    journalctl -u "$SVC_PANEL" -n 12 --no-pager 2>/dev/null | sed 's/^/      /'
  fi
}

set_password() {
  local pw="${1:-}"
  if [[ -z "$pw" ]]; then
    if [[ -t 0 ]]; then
      read -rsp "  new admin password: " pw; echo
      [[ -n "$pw" ]] || die "password cannot be empty"
    else
      pw=$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')
    fi
  fi
  EXITMESH_PASSWORD="$pw" python3 - <<PY
import os, sys
sys.path.insert(0, "$PREFIX")
from exitmesh.store import Store
from exitmesh.panel import hash_password
s = Store("$STATE/exitmesh.db")
s.set_setting("password_hash", hash_password(os.environ["EXITMESH_PASSWORD"]))
import secrets
s.set_setting("session_secret", secrets.token_hex(32))
print("  password set")
PY
  if [[ -t 0 ]] || [[ -n "${1:-}" ]]; then
    printf '  %sadmin password: %s%s\n' "$C_OK" "$pw" "$C_OFF"
  else
    printf '  %sadmin password: %s%s\n' "$C_OK" "$pw" "$C_OFF"
  fi
}

firewall_hint() {
  local port="${PANEL_PORT:-8099}"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    warn "ufw is active — open the panel port yourself if you need remote access:"
    say "      ufw allow $port/tcp"
  fi
  say "  ${C_DIM}the SOCKS router (127.0.0.1:10800) is loopback-only by design${C_OFF}"
}

do_install() {
  need_root
  say ""
  say "  ExitMesh installer"
  say "  ${C_DIM}multi-exit proxy fabric · web panel · SOCKS router${C_OFF}"
  ensure_python
  ensure_xray
  fetch_source
  write_units

  step "setting the admin password"
  if [[ -n "${EXITMESH_PASSWORD:-}" ]]; then
    set_password "$EXITMESH_PASSWORD"
  elif [[ -t 0 ]]; then
    set_password ""
  else
    set_password ""
  fi

  step "done"
  local port="${PANEL_PORT:-8099}"
  local ip; ip=$(curl -fsS -m 4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
  say ""
  say "  panel     http://$ip:$port"
  say "  router    127.0.0.1:10800  ${C_DIM}(socks5, loopback only)${C_OFF}"
  say "  cli       exitmesh list | add | probe | rules"
  say ""
  firewall_hint
  say ""
}

do_update() {
  need_root
  EXITMESH_SRC="" fetch_source
  systemctl restart "$SVC_PANEL"
  sleep 2
  systemctl is-active --quiet "$SVC_PANEL" && ok "updated and restarted" || warn "restart failed"
}

do_uninstall() {
  need_root
  step "removing exitmesh"
  systemctl disable --now "$SVC_PANEL" >/dev/null 2>&1
  rm -f "/etc/systemd/system/$SVC_PANEL.service"
  systemctl daemon-reload
  pkill -f "$PREFIX/run-panel.py" 2>/dev/null
  rm -rf "$PREFIX" /usr/local/bin/exitmesh
  say "  ${C_DIM}kept: $STATE (database) and $CONF — delete them yourself if you want a clean slate${C_OFF}"
  ok "uninstalled"
}

do_status() {
  printf 'service: '; systemctl is-active "$SVC_PANEL" 2>/dev/null || echo inactive
  ss -lntp 2>/dev/null | grep -E ':(8099|10800|200[0-9][0-9])\b' | sed 's/^/  /'
  [[ -x /usr/local/bin/exitmesh ]] && /usr/local/bin/exitmesh list
}

do_panel_url() {
  local listen port
  listen=$(grep -oP 'EXITMESH_LISTEN=\K.*' "/etc/systemd/system/$SVC_PANEL.service" 2>/dev/null || echo 127.0.0.1)
  port=$(grep -oP 'EXITMESH_PORT=\K.*' "/etc/systemd/system/$SVC_PANEL.service" 2>/dev/null || echo 8099)
  echo "http://${listen}:${port}"
}

menu() {
  say ""
  say "  ${C_OK}ExitMesh${C_OFF} — multi-exit proxy fabric"
  say "  ${C_DIM}────────────────────────────────${C_OFF}"
  say "   1) Install / reinstall"
  say "   2) Update"
  say "   3) Show status"
  say "   4) Show panel URL"
  say "   5) Set admin password"
  say "   6) Uninstall"
  say "   0) Exit"
  say ""
  local c; read -rp "  choice: " c
  case "$c" in
    1) do_install ;;
    2) do_update ;;
    3) do_status ;;
    4) do_panel_url ;;
    5) need_root; set_password "" ;;
    6) do_uninstall ;;
    *) exit 0 ;;
  esac
}

case "${1:-}" in
  install)      do_install ;;
  update)       do_update ;;
  uninstall)    do_uninstall ;;
  status)       do_status ;;
  panel-url)    do_panel_url ;;
  set-password) need_root; set_password "${2:-}" ;;
  "")           menu ;;
  *)            say "usage: $0 [install|update|uninstall|status|panel-url|set-password]"; exit 1 ;;
esac
