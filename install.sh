#!/usr/bin/env bash
# ExitMesh installer — one file, idempotent, systemd-native.
#
#   curl -fsSLO https://raw.githubusercontent.com/frank0live/exitmesh/main/install.sh
#   less install.sh && bash install.sh          # read before running as root
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

  # Verify the archive against the checksum published by the release itself.
  # Without this, a hijacked DNS/TLS path or a tampered release asset installs
  # an arbitrary root-owned binary. The .dgst file ships next to the zip in the
  # same release; compare its SHA2-256 line to the file we actually downloaded.
  step "verifying xray checksum"
  if ! curl -fsSL --retry 3 -o "$tmp/x.zip.dgst" "$url.dgst"; then
    rm -rf "$tmp"; die "could not fetch $url.dgst — refusing to install an unverified binary"
  fi
  want=$(sed -n 's/^SHA2-256=[[:space:]]*//p' "$tmp/x.zip.dgst" | head -1 | tr -d '[:space:]')
  [[ -n "$want" ]] || { rm -rf "$tmp"; die "no SHA2-256 in checksum file — refusing to install"; }
  if command -v sha256sum >/dev/null; then
    got=$(sha256sum "$tmp/x.zip" | awk '{print $1}')
  else
    got=$(shasum -a 256 "$tmp/x.zip" | awk '{print $1}')
  fi
  [[ "$got" == "$want" ]] || {
    rm -rf "$tmp"
    die "checksum mismatch for $url (expected $want, got $got) — refusing to install"
  }
  ok "checksum verified (${want:0:16}…)"

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

  # The panel used to run as root. It only needs to write its own state and
  # spawn xray on ports >= 20000, so it runs as a dedicated unprivileged user.
  local run_user="root"
  if [[ "${EXITMESH_NO_USER:-0}" != "1" ]]; then
    if ! id -u exitmesh >/dev/null 2>&1; then
      useradd --system --no-create-home --home-dir "$STATE" \
              --shell /usr/sbin/nologin exitmesh 2>/dev/null \
        || useradd -r -M -d "$STATE" -s /sbin/nologin exitmesh 2>/dev/null || true
    fi
    if id -u exitmesh >/dev/null 2>&1; then
      chown -R exitmesh:exitmesh "$STATE" "$CONF" 2>/dev/null || true
      chmod 750 "$STATE" "$CONF" 2>/dev/null || true
      run_user="exitmesh"
      ok "running as unprivileged user 'exitmesh'"
    else
      warn "could not create the exitmesh user — the panel will run as root"
    fi
  fi

  cat > "/etc/systemd/system/$SVC_PANEL.service" <<EOF
[Unit]
Description=ExitMesh panel and SOCKS router
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$run_user
Group=$run_user
Environment=EXITMESH_DB=$STATE/exitmesh.db
Environment=EXITMESH_XRAY=$XRAY_DIR/xray
Environment=EXITMESH_LISTEN=$listen
Environment=EXITMESH_PORT=$port
Environment=EXITMESH_PASSWORD_FILE=$CONF/initial-password
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 $PREFIX/run-panel.py
Restart=always
RestartSec=3
LimitNOFILE=65535

# Hardening: the panel needs the network, its own state dir, and the ability to
# spawn the xray binary — nothing else. NoNewPrivileges makes any setuid helper
# useless, ProtectSystem=strict makes the rest of the filesystem read-only, and
# the syscall/address-family filters cut off whole classes of post-exploitation.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=no
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
ReadWritePaths=$STATE $CONF

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
  # Only echo the password back to a human at an interactive terminal. When the
  # installer runs unattended, printing it would drop the secret into CI logs,
  # shell history or a provisioning transcript, so write it to a 0600 file and
  # point at that instead.
  if [[ -t 1 ]]; then
    printf '  %sadmin password: %s%s\n' "$C_OK" "$pw" "$C_OFF"
  else
    local pwfile="$CONF/initial-password"
    umask 077
    printf '%s\n' "$pw" > "$pwfile"
    chmod 600 "$pwfile"
    printf '  %sadmin password written to %s (mode 0600) — read it, then delete it%s\n' \
      "$C_OK" "$pwfile" "$C_OFF"
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
  local listen="${PANEL_LISTEN:-127.0.0.1}"
  say ""
  # Print a URL that actually reaches the panel. Advertising
  # http://<public-ip>:<port> was wrong twice over: the panel binds loopback by
  # default, and that URL puts the admin password on the wire in cleartext.
  if [[ "$listen" == "127.0.0.1" || "$listen" == "localhost" || "$listen" == "::1" ]]; then
    say "  panel     http://127.0.0.1:$port  ${C_DIM}(loopback only)${C_OFF}"
    say "            ${C_DIM}reach it over an SSH tunnel:${C_OFF}"
    say "            ${C_DIM}ssh -N -L $port:127.0.0.1:$port root@<server>${C_OFF}"
    say "            ${C_DIM}then open http://127.0.0.1:$port in your browser${C_OFF}"
  else
    say "  panel     http://$listen:$port"
    warn "the panel is bound to a non-loopback address — put TLS in front of it"
    say "            ${C_DIM}the admin password and session cookie are otherwise sent in cleartext${C_OFF}"
  fi
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
