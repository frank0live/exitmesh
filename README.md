<div align="center">

# 🌐 ExitMesh

**One stable SOCKS5 endpoint in front of many upstream exits — health-ranked, sticky, self-healing.**

[![Python](https://img.shields.io/badge/Python-3.9%2B%20(Stdlib%20Only)-blue.svg)](#-features)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)](#-features)
[![Protocols](https://img.shields.io/badge/Upstreams-VLESS%20%7C%20VMess%20%7C%20Trojan%20%7C%20SS%20%7C%20SOCKS5-orange.svg)](#-features)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(systemd)-lightgrey.svg)](#-install)
[![Security](https://img.shields.io/badge/Security-Hardened-purple.svg)](#-security--threat-model)

[Why ExitMesh?](#-why-this-exists) • [Features](#-features) • [Installation](#-install) • [CLI & Usage](#-cli--management) • [Routing Rules](#-routing-rules) • [Security](#-security--threat-model)

</div>

---

You have ten proxies: some VLESS, some VMess, some SOCKS5 boxes in other countries. Your scripts keep pointing at the dead one, your scrapers lose their session, and you have no idea which exit burned 40 GB last night. **ExitMesh turns that pile into a single local port.**

```text
                       ┌──────────────────────────────────────────┐
                       │                 ExitMesh                 │
  curl / browser /     │  :10800  SOCKS5 router                   │
  scraper / bot  ──────┤                                          │
                       │            ├── selector ── rules         │
                       │            │      ├── health score       │
                       │            │      ├── circuit breaker    │
                       │            │      └── sticky sessions    │
                       │            │                             │
                       │     ┌──────┴───────────┬──────────┬───┐  │
                       │   :20000       :20001     :20002    ...  │
                       │   xray/vless   xray/vmess  xray/ss       │
                       └────────────┬───────────┬──────────┬──────┘
                                    ▼           ▼          ▼
                                frankfurt   amsterdam   singapore
```

<p align="center">
  <img src="docs/panel.png" alt="ExitMesh panel — exit ranking, health and per-exit traffic" width="100%">
</p>

## 💡 Why This Exists

Most "proxy pool" projects are just a rotating list and a `random.choice()`. That fails in three ways: it sends traffic to dead exits, it breaks sessions that need a stable IP, and it tells you nothing about where your bandwidth went.

ExitMesh is built around the three things that actually matter in production:

1. **Health-Aware Ranking:** Every exit is probed on a schedule for both *real latency* and its *real egress IP* (not just "port is open"). Ranking is a deterministic score, not a coin flip:
   ```text
   score = weight × health_factor / (1 + latency_ms / 120) / (1 + consecutive_failures × 0.5)
   ```
   A dead exit scores `0` and is never chosen. A flapping exit is penalized until it proves itself again.

2. **Sticky Sessions:** A client keeps the same exit for `sticky_ttl` seconds (default: 15 min), so logins, shopping carts, and scraping sessions survive. The session table is keyed by client address and expires automatically.

3. **Per-Exit Accounting:** Up/down bytes, connection counts, and failure counts are tracked per exit and batched into SQLite every few seconds — zero disk write overhead per packet.

---

## ✨ Features

* **Any Upstream Format:** Paste a `vless://`, `vmess://`, `trojan://`, or `ss://` share link and ExitMesh generates, validates, and supervises an isolated Xray instance for it. Already have raw SOCKS5 boxes? Just add `host:port` and you're done.
* **Automatic Failover:** If the chosen exit refuses mid-connection, the next highest-ranked exit is seamlessly tried before the client ever sees an error.
* **Circuit Breaker:** N consecutive failures trip the breaker with exponential backoff (`15s` → `300s`); a single successful probe closes it.
* **Granular Routing Rules:** First-match-wins evaluation on `domain` (suffix or glob), `port`, `client` (exact IP, CIDR, or glob), or `default`. Supported actions: `auto`, a specific exit ID, `direct`, or `block`.
* **Process Supervision:** Dead Xray processes are automatically restarted by the probe loop. Generated configs are pre-validated via `xray run -test` before loading.
* **Built-in Web Panel:** Dark-mode dashboard featuring live KPIs, real-time exit rankings, per-exit bandwidth usage, an inline rules editor, and an audit log. Built with vanilla JS — no framework, no build step.
* **Fully Auditable:** Every login attempt, exit modification, rule update, and circuit-breaker trip is recorded in the audit table.
* **Zero Dependencies:** Runs exclusively on the Python 3.9+ standard library. A single external binary (`xray`) is optional and only required if you use share-link exits.

---

## 🚀 Install

Download the installer, inspect it, and run it — **never pipe a remote file straight into a root shell**:

```bash
curl -fsSLO https://raw.githubusercontent.com/frank0live/exitmesh/main/install.sh
less install.sh          # inspect the script first
sudo bash install.sh
```

**What the idempotent installer does:**
1. Installs `python3` if missing.
2. Fetches `xray-core` for your CPU architecture (skipped if already present) and **verifies it against the official SHA2-256 `.dgst` checksum**.
3. Installs the application to `/opt/exitmesh`.
4. Registers and starts a hardened `systemd` unit running as an unprivileged `exitmesh` user.

### Accessing the Web Panel

By default, the panel binds strictly to `127.0.0.1`. Reach it securely via an SSH local port forward rather than exposing it to the public internet:

```bash
ssh -N -L 8099:127.0.0.1:8099 root@your-server
# Then open http://127.0.0.1:8099 in your local browser
```

> **🔑 Initial Password:** The generated admin password is written to `/etc/exitmesh/initial-password` (`chmod 0600`) rather than printed to `journald` logs. Read it once, log in, and delete the file.

**Non-Interactive / Automated Install:**
```bash
EXITMESH_PASSWORD='choose-something-long' PANEL_PORT=8099 sudo -E bash install.sh install
```

---

## 🛠 CLI & Management

Authenticate once, then manage exits, trigger probes, and update routing rules directly from the terminal:

```bash
exitmesh login                          # Authenticate; caches a session cookie in ~/.exitmesh-cookie (0600)
exitmesh list                           # View exits, health scores, and traffic
exitmesh add fra-1 --link 'vless://...' # Add an Xray-backed share link exit
exitmesh add local --endpoint 10.0.0.5:1080 # Add a raw SOCKS5 upstream
exitmesh probe                          # Probe all exits immediately
exitmesh probe fra-1                    # Probe a specific exit
exitmesh rules --file rules.json        # Load routing rules from a JSON file
exitmesh start fra-1                    # Enable an exit
exitmesh stop fra-1                     # Disable an exit
exitmesh restart fra-1                  # Restart an exit's supervisor
exitmesh export                         # Dump full state and metrics as JSON
exitmesh status                         # systemd status of panel + router
exitmesh logs                           # Tail the panel journal
```

> The CLI talks to the panel over its HTTP API, so every command except `login` and `url` needs a session cookie. Set `EXITMESH_URL` if the panel does not listen on the default `http://127.0.0.1:8099`.

---

## 🔌 Usage

Point any application, browser, or scraper at `127.0.0.1:10800` using `socks5h` (so DNS resolution happens through the exit):

**cURL:**
```bash
curl --socks5-hostname 127.0.0.1:10800 https://api.ipify.org
```

**Python (`requests`):**
```python
import requests

proxies = {
    "http": "socks5h://127.0.0.1:10800",
    "https": "socks5h://127.0.0.1:10800",
}
print(requests.get("https://api.ipify.org", proxies=proxies, timeout=20).text)
```

> **Note:** The SOCKS5 listener binds to loopback intentionally and has **no authentication**. If you need to reach it from other machines, place it behind WireGuard, an SSH tunnel, or an authenticated frontend proxy rather than exposing the raw port.

---

## 🧭 Routing Rules

Rules are evaluated top-to-bottom; **first match wins**. Place `{"match": {"default": true}}` at the end as your catch-all rule.

```json
{
  "rules": [
    {"match": {"domain": "netflix.com"},     "exit": "ams-2"},
    {"match": {"domain": "openai.com"},      "exit": "fra-1"},
    {"match": {"domain": "doubleclick.net"}, "exit": "block"},
    {"match": {"port": [25, 465, 587]},      "exit": "block"},
    {"match": {"client": "192.168.1.*"},     "exit": "direct"},
    {"match": {"default": true},             "exit": "auto"}
  ]
}
```

* **`domain`**: Matches the root domain, any subdomain, or wildcard globs (`*.example.com`).
* **`client`**: Matches the client address as an exact IP (`192.168.1.5`), a CIDR network (`10.0.0.0/8`, `fd00::/8`), or a glob (`192.168.1.*`).
* **`exit`**: Accepts a specific exit ID (e.g., `fra-1`), `auto` (highest-ranked healthy exit), `direct` (server's native IP), or `block`.

---

## 🏗 Architecture

| Component | File | Responsibility |
| :--- | :--- | :--- |
| **SOCKS5 Router** | `exitmesh/socks.py` | Accepts client connections, selects upstream exit, pumps bytes, and records traffic. |
| **Selector** | `exitmesh/selector.py` | Evaluates rules → sticky sessions → weighted health scores; manages circuit breakers. |
| **Prober** | `exitmesh/probe.py` | Measures real round-trip latency, egress IP, and GeoIP country through the exit itself. |
| **Xray Supervisor** | `exitmesh/xray.py` | Parses share links, generates/validates Xray configs, spawns and monitors child processes. |
| **Storage Engine** | `exitmesh/store.py` | SQLite persistence for exits, health time-series, batched traffic counters, settings, and audit logs. |
| **Web Panel** | `exitmesh/panel.py` | HTTP API and static UI server, HMAC-signed cookie sessions, and PBKDF2 authentication. |

---

## 🔒 Security & Threat Model

### Defense-in-Depth Measures
* **Authentication & Sessions:** Admin passwords use `PBKDF2-SHA256` (200,000 iterations). Sessions rely on stateless HMAC-signed cookies (`HttpOnly`, `SameSite=Strict`, and automatic `Secure` flag detection over TLS / `X-Forwarded-Proto: https`). Login endpoints are rate-limited to 5 failed attempts per IP per 5 minutes.
* **Path Traversal Prevention:** Exit IDs are sanitized through `store.safe_exit_id()` (strictly allowing `[a-z0-9._-]` and collapsing `..`). Additionally, `xray.conf_path()` independently verifies that targets resolve to a single plain filename inside `/etc/exitmesh/xray/`.
* **XSS Mitigation:** Exit names and dynamic values are rendered strictly via `esc()` and `dataset` attributes. There are zero string-concatenated inline `onclick` handlers in the DOM.
* **Systemd Sandboxing:** Runs as an unprivileged `exitmesh` user with `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `RestrictSUIDSGID`, `RestrictNamespaces`, `LockPersonality`, and `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`.
* **Supply-Chain Verification:** The `xray-core` release archive is verified against its published `SHA2-256` `.dgst` file before extraction; any mismatch immediately aborts installation.
* **Loopback Enforcement:** The unauthenticated SOCKS5 listener refuses to bind to non-loopback interfaces unless `EXITMESH_ALLOW_PUBLIC_SOCKS=1` is explicitly set in the environment, and the web API rejects non-loopback `router_listen` payloads with `HTTP 400`.

### Threat Model
Because the SOCKS5 listener is restricted to `127.0.0.1`, the primary attack surface is **panel compromise** or **admin misconfiguration**.

If you choose to expose the web panel beyond loopback, **always terminate TLS in front of it** (via Nginx, Caddy, or an SSH tunnel) and pass `X-Forwarded-Proto: https`. Exposing the raw HTTP port over a public network transmits credentials and session cookies in cleartext.

---

## 🧪 Testing & Verification

Run the offline unit and integration suite (zero external network access required):

```bash
python3 tests/test_exitmesh.py
```

That one command runs **both modules — 33 test functions, 121 assertions, no network access required:**

- [x] Share-link parsing across VLESS, VMess, Trojan, and Shadowsocks.
- [x] Xray config generation, store CRUD operations, and traffic batching.
- [x] Health-score ranking order, routing rule evaluation, and circuit-breaker state transitions.
- [x] Live end-to-end SOCKS5 byte-accurate echo tests and automatic failover when the top exit drops.
- [x] Security and honesty regressions:
  - `safe_exit_id` and `xray.conf_path()` block `../../x`, absolute paths, and directory separators.
  - Panel and listener reject public `0.0.0.0` binds without explicit environment overrides.
  - Startup sequence writes initial credentials to a `0600` file without leaking secrets to stdout/logs.
  - Generated Xray `direct` fallback rules blackhole RFC1918, loopback, link-local (cloud metadata `169.254.169.254`), CGNAT, and IPv6 ULA ranges.
  - `client` rules accept an exact IP, a CIDR network, and a glob, and a CIDR rule really steers the pick.
  - A breaker trip is written to the audit table once per opening, and the panel wires the callback.
  - The committed `systemd/exitmesh-panel.service` stays unprivileged and sandboxed.
  - The installer verifies the Xray archive against the release `.dgst` before extraction.

`tests/test_security.py` also runs on its own if you want just the security regressions.

**Live Exploit Verification Suite:**
`tests/exploit_check.py` boots a real panel on an ephemeral loopback port and *performs* the attacks instead of asserting on source strings — it creates an exit named `../../pwned` and walks the filesystem for anything written outside the config dir, stores a name containing `'); alert(...)` and inspects the served HTML, POSTs `router_listen: 0.0.0.0` and expects `400`, checks the cookie gains `Secure` behind `X-Forwarded-Proto: https`, and asserts the generated password never reaches stdout. It cleans up its own process and temp dir, so it is safe to re-run:

```bash
python3 tests/exploit_check.py
```

---

## 🗑 Uninstall

```bash
bash install.sh uninstall
```
*Note: `/var/lib/exitmesh` (SQLite database) and `/etc/exitmesh` (configurations) are preserved on uninstall. Remove them manually if you want a complete wipe.*

---

## 💬 Support

* **Telegram:** [@master_supports](https://t.me/master_supports)
* Found a bug or have a feature request? Open an issue in the [GitHub Issues](https://github.com/frank0live/exitmesh/issues) tab.
