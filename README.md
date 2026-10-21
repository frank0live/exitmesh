# ExitMesh

**One stable SOCKS5 endpoint in front of many upstream exits — health-ranked, sticky, self-healing.**

You have ten proxies: some VLESS, some VMess, some SOCKS5 boxes in other countries. Your
scripts keep pointing at the dead one, your scrapers lose their session, and you have no idea
which exit burned 40 GB last night. ExitMesh turns that pile into a single local port.

```
                       ┌──────────────────────────────────────────┐
  curl / browser /     │              ExitMesh                    │
  scraper / bot  ──────┤  :10800  SOCKS5 router                   │
                       │            │                             │
                       │            ├── selector ── rules          │
                       │            │      ├── health score       │
                       │            │      ├── circuit breaker    │
                       │            │      └── sticky sessions    │
                       │            │                             │
                       │     ┌──────┴──────┬──────────┬─────────┐ │
                       │  :20000       :20001     :20002    ...  │
                       │  xray/vless   xray/vmess  xray/ss       │
                       └──────┬──────────┬──────────┬─────────┘
                              ▼          ▼          ▼
                          frankfurt   amsterdam   singapore
```

<p align="center">
  <img src="docs/panel.png" alt="ExitMesh panel" width="100%">
</p>

## Why this exists

Most "proxy pool" projects are a rotating list and a `random.choice()`. That fails in three
ways: it sends traffic to dead exits, it breaks sessions that need a stable IP, and it tells
you nothing about where your bandwidth went. ExitMesh is built around the three things that
actually matter in production:

**Health-aware ranking.** Every exit is probed on a schedule: real latency *and* its real
egress IP (not just "port is open"). Ranking is a score, not a coin flip:

```
score = weight × health_factor / (1 + latency_ms/120) / (1 + consecutive_failures × 0.5)
```

A dead exit scores `0` and is never chosen. A flapping exit is penalised until it proves
itself again.

**Sticky sessions.** A client keeps the same exit for `sticky_ttl` seconds (default 15 min),
so logins, carts and scraping sessions survive. The table is keyed by client address and
expires on its own.

**Per-exit accounting.** Up/down bytes, connection count and failure count per exit, batched
into SQLite every few seconds — no write per packet.

## Features

- **Any upstream format** — paste a `vless://`, `vmess://`, `trojan://` or `ss://` share link
  and ExitMesh generates, validates and supervises an isolated Xray instance for it. Already
  have SOCKS5 boxes? Add `host:port` and you're done.
- **Automatic failover** — if the chosen exit refuses mid-connection, the next best one is
  tried before the client sees an error.
- **Circuit breaker** — N consecutive failures open the breaker with exponential backoff
  (15s → 300s); a single success closes it.
- **Routing rules** — first match wins, on `domain` (suffix or glob), `port`, `client` CIDR/glob,
  or `default`. Actions: `auto`, a specific exit, `direct`, or `block`.
- **Process supervision** — dead Xray processes are restarted by the probe loop; configs are
  validated with `xray run -test` before they are ever loaded.
- **Web panel** — dark dashboard with live KPIs, exit ranking, per-exit traffic, an inline
  rules editor and an audit log. No JS framework, no build step.
- **Auditable** — every login, exit change, rule change and breaker trip lands in the audit
  table.
- **Zero dependencies** — Python 3.9+ standard library only. One binary (`xray`) is optional
  and only needed for share-link exits.

## Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/frank0live/exitmesh/main/install.sh)
```

The installer is idempotent and does four things: installs Python if missing, fetches
`xray-core` for your architecture (skipped if present), copies the app to `/opt/exitmesh`,
and writes a hardened systemd unit. It prints the panel URL and the generated admin password
at the end.

Non-interactive:

```bash
EXITMESH_PASSWORD='choose-something-long' bash install.sh install
PANEL_PORT=8099 bash install.sh install
```

Manage it:

```bash
exitmesh list                 # exits, health, traffic
exitmesh add fra-1 --link 'vless://...'
exitmesh add local --endpoint 10.0.0.5:1080
exitmesh probe                # probe every exit now
exitmesh probe fra-1
exitmesh rules --file rules.json
exitmesh start fra-1          # enable
exitmesh stop fra-1
exitmesh restart fra-1
exitmesh export               # full status as JSON
```

## Use it

Point anything at `127.0.0.1:10800` as a SOCKS5 proxy:

```bash
curl --socks5-hostname 127.0.0.1:10800 https://api.ipify.org
```

```python
import requests
proxies = {"https": "socks5h://127.0.0.1:10800", "http": "socks5h://127.0.0.1:10800"}
print(requests.get("https://api.ipify.org", proxies=proxies, timeout=20).text)
```

The router binds to loopback on purpose. To expose it, put your own auth in front of it
(SSH tunnel, WireGuard, or an authenticated proxy) rather than editing the bind address —
ExitMesh's SOCKS5 listener has **no authentication**.

## Routing rules

Rules are evaluated top to bottom; the first match wins. `{"match": {"default": true}}` is
the catch-all and should be last.

```json
{
  "rules": [
    {"match": {"domain": "netflix.com"},              "exit": "ams-2"},
    {"match": {"domain": "openai.com"},               "exit": "fra-1"},
    {"match": {"domain": "doubleclick.net"},          "exit": "block"},
    {"match": {"port": [25, 465, 587]},               "exit": "block"},
    {"match": {"client": "192.168.1.*"},              "exit": "direct"},
    {"match": {"default": true},                      "exit": "auto"}
  ]
}
```

`domain` matches the host itself, any subdomain, and globs (`*.example.com`). `exit` accepts
an exit id, `auto` (ranked selection), `direct` (server's own IP) or `block`.

## How the pieces fit

| Component | File | Responsibility |
|---|---|---|
| SOCKS5 router | `exitmesh/socks.py` | Accepts clients, picks an exit, pumps bytes, counts traffic |
| Selector | `exitmesh/selector.py` | Rules → stickiness → weighted score; owns the circuit breaker |
| Probes | `exitmesh/probe.py` | Latency + real exit IP + country, through the exit itself |
| Xray supervisor | `exitmesh/xray.py` | Parses share links, writes configs, validates, spawns, restarts |
| Store | `exitmesh/store.py` | SQLite: exits, health series, traffic, settings, audit |
| Panel | `exitmesh/panel.py` | HTTP API + static UI, signed-cookie auth, PBKDF2 passwords |

## Security notes

- Panel binds to `127.0.0.1` by default; passwords are PBKDF2-SHA256 (200k rounds).
- Sessions are HMAC-signed cookies — no server-side session table to leak or grow.
- Login is rate-limited: 5 failures per IP per 5 minutes.
- Xray configs are written `0600` to `/etc/exitmesh/xray/`.
- The systemd unit runs with `NoNewPrivileges`, `PrivateTmp` and a restricted
  `ReadWritePaths` set.
- **The SOCKS5 router itself is unauthenticated.** Keep it on loopback.

## Tests

```bash
python3 tests/test_exitmesh.py
```

14 tests, no network required: link parsing for all four protocols, Xray config shape,
store CRUD and traffic aggregation, ranking order, rule matching and blocking, breaker
open/recover, and two live end-to-end router tests (byte-accurate echo through a real
SOCKS5 fixture, plus failover when the top-ranked exit is dead).

```
14 passed, 0 failed
```

## Uninstall

```bash
bash install.sh uninstall
```

Keeps `/var/lib/exitmesh` (your database) and `/etc/exitmesh` — delete them yourself for a
clean slate.

## License

MIT
