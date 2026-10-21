"""ExitMesh panel — HTTP API + static UI. Stdlib only, no framework."""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .probe import probe_direct, probe_tcp, probe_via_socks
from .selector import Breaker, Selector
from .socks import Router, StatsBuffer
from .store import Store
from .xray import SUPPORTED, XraySupervisor, parse_link

SESSION_TTL = 12 * 3600
PBKDF2_ROUNDS = 200_000
MAX_BODY = 512 * 1024


# ------------------------------------------------------------------ passwords
def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt}${dk.hex()}"


def verify_password(pw, stored):
    try:
        algo, rounds, salt, hexdigest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(dk.hex(), hexdigest)
    except Exception:
        return False


class Sessions:
    """Signed cookies: base64(payload).hmac — no server-side session table."""

    def __init__(self, secret):
        self.secret = secret.encode()

    def issue(self, user="admin"):
        payload = json.dumps({"u": user, "exp": int(time.time()) + SESSION_TTL}).encode()
        b = payload.hex()
        sig = hmac.new(self.secret, b.encode(), hashlib.sha256).hexdigest()[:32]
        return f"{b}.{sig}"

    def check(self, token):
        if not token or "." not in token:
            return False
        b, sig = token.rsplit(".", 1)
        want = hmac.new(self.secret, b.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, want):
            return False
        try:
            d = json.loads(bytes.fromhex(b))
        except Exception:
            return False
        return d.get("exp", 0) > time.time()


class App:
    """Wires storage, selector, router, supervisor and the probe worker together."""

    def __init__(self, db_path, xray_bin="/usr/local/bin/xray",
                 web_root=None, listen="127.0.0.1"):
        self.store = Store(db_path)
        self.breaker = Breaker(int(self.store.get_setting("unhealthy_after", "3")))
        self.selector = Selector(
            self.store, self.breaker,
            timeout=float(self.store.get_setting("health_timeout", "6")),
        )
        self.stats = StatsBuffer(self.store)
        self.router = Router(
            self.store, self.selector,
            listen=self.store.get_setting("router_listen", "127.0.0.1"),
            port=int(self.store.get_setting("router_socks_port", "10800")),
            sticky_ttl=int(self.store.get_setting("sticky_ttl", "900")),
            stats=self.stats,
        )
        self.xray = XraySupervisor(xray_bin, "/etc/exitmesh/xray", self.store)
        self.web_root = web_root or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
        self.listen = listen
        self.port = int(self.store.get_setting("panel_port", "8099"))
        self.sessions = Sessions(self._secret())
        self.login_attempts = {}     # ip -> [count, first_ts]
        self.last_probe = {}         # eid -> ts
        self.probe_lock = threading.Lock()
        self.started_at = int(time.time())

    # ------------------------------------------------------------------ auth
    def _secret(self):
        s = self.store.get_setting("session_secret")
        if not s:
            s = secrets.token_hex(32)
            self.store.set_setting("session_secret", s)
        return s

    def rotate_secret(self):
        self.store.set_setting("session_secret", secrets.token_hex(32))
        self.sessions = Sessions(self._secret())

    def has_password(self):
        return bool(self.store.get_setting("password_hash"))

    def set_password(self, pw):
        self.store.set_setting("password_hash", hash_password(pw))
        self.rotate_secret()

    def check_password(self, pw):
        stored = self.store.get_setting("password_hash") or ""
        return verify_password(pw, stored)

    def locked(self, ip):
        rec = self.login_attempts.get(ip)
        if not rec:
            return False, 0
        count, first = rec
        if time.time() - first > 300:
            self.login_attempts.pop(ip, None)
            return False, 0
        if count >= 5:
            return True, int(300 - (time.time() - first))
        return False, 0

    def note_failure(self, ip):
        rec = self.login_attempts.get(ip)
        if not rec or time.time() - rec[1] > 300:
            self.login_attempts[ip] = [1, time.time()]
        else:
            rec[0] += 1

    # ---------------------------------------------------------------- probes
    def probe_one(self, eid):
        e = self.store.get_exit(eid)
        if not e:
            return {"ok": False, "error": "no such exit"}
        try:
            if e["kind"] == "socks5":
                host, _, p = (e.get("endpoint") or "").rpartition(":")
                if not p:
                    return {"ok": False, "error": "endpoint must be host:port"}
                r = probe_via_socks(host or "127.0.0.1", int(p),
                                    timeout=float(self.store.get_setting("health_timeout", "6")))
            elif e["kind"] in SUPPORTED:
                port = int(e.get("socks_port") or 0)
                if not port:
                    return {"ok": False, "error": "no socks port assigned"}
                r = probe_via_socks("127.0.0.1", port,
                                    timeout=float(self.store.get_setting("health_timeout", "6")))
            elif e["kind"] == "direct":
                r = probe_direct()
            else:
                host, _, p = (e.get("endpoint") or "").rpartition(":")
                r = probe_tcp(host, int(p or 0))
        except Exception as ex:
            r = {"ok": False, "error": str(ex)[:160]}

        self.store.record_health(eid, r.get("ok", False), r.get("latency_ms"),
                                 r.get("exit_ip"), r.get("country"), r.get("error", ""))
        self.breaker.record(eid, r.get("ok", False), r.get("latency_ms"))
        self.last_probe[eid] = int(time.time())
        return r

    def probe_all(self):
        with self.probe_lock:
            out = {}
            for e in self.store.list_exits():
                if e.get("enabled"):
                    out[e["id"]] = self.probe_one(e["id"])
            return out

    # ------------------------------------------------------------- lifecycle
    def sync_xray(self):
        """Start an xray instance for every enabled xray-type exit."""
        port = 20000
        for e in self.store.list_exits():
            if e["kind"] not in SUPPORTED:
                continue
            if not e.get("link"):
                continue
            if not e.get("socks_port"):
                used = {x.get("socks_port") for x in self.store.list_exits()}
                while port in used:
                    port += 1
                self.store.update_exit(e["id"], socks_port=port)
                e["socks_port"] = port
            try:
                parsed = parse_link(e["link"])
                path = self.xray.write_config(e["id"], parsed, e["socks_port"])
                ok, msg = self.xray.validate(path)
                if not ok:
                    self.store.log("system", "xray-invalid", f"{e['id']}: {msg}")
                    continue
                if e.get("enabled") and not self.xray.alive(e["id"]):
                    self.xray.start(e["id"])
            except Exception as ex:
                self.store.log("system", "xray-error", f"{e['id']}: {ex}")

    def stop(self):
        try:
            self.xray.stop_all()
        except Exception:
            pass


# ------------------------------------------------------------------- handler
def demo_status():
    """Canned, believable data for screenshots. Only reachable with EXITMESH_DEMO=1."""
    now = int(time.time())

    def ex(eid, name, kind, endpoint, ip, country, lat, weight, ok, up, down,
           conns, age, error=""):
        return {
            "id": eid, "name": name, "kind": kind, "endpoint": endpoint,
            "socks_port": 20000, "weight": weight, "enabled": 1, "note": "",
            "created_at": now - 86400,
            "health": {"ok": ok, "ts": now - age, "latency_ms": lat if ok else None,
                       "exit_ip": ip if ok else None,
                       "country": country if ok else None,
                       "error": error},
            "breaker": {"fails": 0 if ok else 3, "until": 0, "latency": lat, "ok": ok},
            "traffic": {"up": up, "down": down, "conns": conns,
                        "failures": 0 if ok else 12},
            "running": True,
        }

    exits = [
        ex("fra-1", "frankfurt-1", "vless", "de1.exitmesh.io:443", "45.83.107.22",
           "Germany", 38, 150, True, 812_004_331, 9_447_112_884, 1284, 22),
        ex("ams-2", "amsterdam-2", "vmess", "nl2.exitmesh.io:8443", "185.104.184.71",
           "Netherlands", 54, 120, True, 402_881_204, 6_118_330_902, 733, 41),
        ex("ist-3", "istanbul-3", "trojan", "tr3.exitmesh.io:443", "178.20.44.19",
           "Türkiye", 71, 100, True, 156_772_910, 2_004_551_338, 291, 63),
        ex("sgp-4", "singapore-4", "vless", "sg4.exitmesh.io:443", None, None,
           None, 80, False, 88_102_774, 903_221_880, 141, 148,
           "i/o timeout after 6000ms"),
    ]
    return {
        "ok": True,
        "version": __version__,
        "uptime": 2_204_317,
        "router": {"listen": "127.0.0.1", "port": 10800, "connections": 2_449,
                   "sticky": 37},
        "exits": exits,
        "active_exit": "fra-1",
        "ranking": [
            {"id": "fra-1", "score": 118.42, "latency_ms": 38},
            {"id": "ams-2", "score": 92.10, "latency_ms": 54},
            {"id": "ist-3", "score": 71.55, "latency_ms": 71},
            {"id": "sgp-4", "score": 0.0, "latency_ms": None},
        ],
        "direct": {"ok": True, "latency_ms": 9, "exit_ip": "203.0.113.42",
                   "country": "Germany", "country_code": "DE", "error": ""},
    }


DEMO_RULES = [
    {"match": {"domain": "netflix.com"}, "exit": "ams-2"},
    {"match": {"domain": "openai.com"}, "exit": "fra-1"},
    {"match": {"domain": "ads.example", "port": [80, 443]}, "exit": "block"},
    {"match": {"default": True}, "exit": "auto"},
]


def demo_audit(limit=40):
    now = int(time.time())
    rows = [
        ("admin", "exit-add", "fra-1 (vless)"),
        ("admin", "rules-update", "4 rules"),
        ("system", "failover", "sgp-4 unhealthy -> fra-1"),
        ("system", "xray-restart", "ams-2: pid 28411"),
        ("admin", "exit-probe", "ist-3 71ms"),
        ("system", "probe", "4 exits, 3 healthy"),
        ("admin", "settings", '{"sticky_ttl": "900"}'),
        ("system", "breaker-open", "sgp-4 after 3 failures"),
    ]
    out = []
    for i, (actor, action, detail) in enumerate(rows):
        out.append({"ts": now - i * 197, "actor": actor, "action": action,
                    "detail": detail})
    return out[:limit]


class Handler(BaseHTTPRequestHandler):
    app: "App" = None  # type: ignore[assignment]
    server_version = "exitmesh/" + __version__
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------- utilities
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body=b"", ctype="application/json; charset=utf-8",
              extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str))

    def err(self, code, msg):
        self.json({"ok": False, "error": msg}, code)

    def body_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if n <= 0 or n > MAX_BODY:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def client_ip(self):
        return self.client_address[0]

    def session_ok(self):
        c = SimpleCookie(self.headers.get("Cookie") or "")
        m = c.get("em_sess")
        return bool(m and self.app.sessions.check(m.value))

    # ---------------------------------------------------------------- routing
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")

    def route(self, method):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        # ---- public
        if path in ("/", "/index.html") and method == "GET":
            return self.serve_static("index.html")
        if path.startswith("/static/"):
            return self.serve_static(path[8:])
        if path == "/api/login" and method == "POST":
            return self.api_login()
        if path == "/api/health":
            return self.json({"ok": True, "version": __version__,
                              "uptime": int(time.time()) - self.app.started_at})
        if path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")

        # ---- authenticated
        if not self.session_ok():
            if path.startswith("/api/"):
                return self.err(401, "unauthorized")
            return self.serve_static("index.html")

        if path == "/api/logout" and method == "POST":
            return self._send(200, b"{}", extra={
                "Set-Cookie": "em_sess=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if path == "/api/status" and method == "GET":
            return self.api_status()
        if path == "/api/exits" and method == "GET":
            return self.api_list_exits()
        if path == "/api/exits" and method == "POST":
            return self.api_add_exit()
        if path == "/api/rules" and method == "GET":
            if os.environ.get("EXITMESH_DEMO") == "1":
                return self.json({"ok": True, "rules": DEMO_RULES})
            return self.json({"ok": True, **self.app.store.rules()})
        if path == "/api/rules" and method == "POST":
            return self.api_set_rules()
        if path == "/api/settings" and method == "GET":
            s = self.app.store.all_settings()
            s.pop("password_hash", None)
            s.pop("session_secret", None)
            return self.json({"ok": True, "settings": s})
        if path == "/api/settings" and method == "POST":
            return self.api_set_settings()
        if path == "/api/audit" and method == "GET":
            if os.environ.get("EXITMESH_DEMO") == "1":
                return self.json({"ok": True, "items": demo_audit(int(q.get("limit", 40))) })
            return self.json({"ok": True,
                              "items": self.app.store.recent_audit(int(q.get("limit", 100)))})
        if path == "/api/probe" and method == "POST":
            return self.json({"ok": True, "results": self.app.probe_all()})
        if path == "/api/password" and method == "POST":
            return self.api_password()

        # ---- /api/exits/<id>/<action>
        parts = path.strip("/").split("/")
        if len(parts) >= 4 and parts[0] == "api" and parts[1] == "exits":
            eid, action = parts[2], parts[3]
            if method == "DELETE" and len(parts) == 3:
                return self.api_delete_exit(eid)
            if method == "POST":
                return self.api_exit_action(eid, action, q)
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "exits" and method == "DELETE":
            return self.api_delete_exit(parts[2])
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "exits" and method == "GET" \
                and parts[3] == "history":
            return self.json({"ok": True,
                              "items": self.app.store.health_series(parts[2], 60)})
        return self.err(404, "not found")

    # ---------------------------------------------------------------- static
    def serve_static(self, name):
        name = name.replace("..", "").lstrip("/")
        full = os.path.join(self.app.web_root, name)
        if not os.path.isfile(full):
            return self.err(404, "not found")
        ext = os.path.splitext(full)[1].lower()
        ctype = {".html": "text/html; charset=utf-8",
                 ".css": "text/css; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".svg": "image/svg+xml",
                 ".png": "image/png",
                 ".woff2": "font/woff2"}.get(ext, "application/octet-stream")
        with open(full, "rb") as f:
            data = f.read()
        self._send(200, data, ctype)

    # ------------------------------------------------------------------ auth
    def api_login(self):
        ip = self.client_ip()
        locked, wait = self.app.locked(ip)
        if locked:
            return self.err(429, f"too many attempts, wait {wait}s")
        b = self.body_json()
        pw = str(b.get("password") or "")
        if not pw or not self.app.check_password(pw):
            self.app.note_failure(ip)
            self.app.store.log(ip, "login-failed", "")
            return self.err(401, "wrong password")
        self.app.login_attempts.pop(ip, None)
        self.app.store.log(ip, "login", "")
        token = self.app.sessions.issue()
        self._send(200, json.dumps({"ok": True, "version": __version__}),
                   extra={"Set-Cookie":
                          f"em_sess={token}; Path=/; Max-Age={SESSION_TTL}; "
                          "HttpOnly; SameSite=Strict"})

    def api_password(self):
        b = self.body_json()
        old, new = str(b.get("old") or ""), str(b.get("new") or "")
        if not self.app.check_password(old):
            return self.err(403, "current password is wrong")
        if len(new) < 8:
            return self.err(400, "new password must be at least 8 characters")
        self.app.set_password(new)
        self.app.store.log(self.client_ip(), "password-change", "")
        return self.json({"ok": True, "note": "all sessions signed out"})

    # ------------------------------------------------------------------ data
    def api_status(self):
        if os.environ.get("EXITMESH_DEMO") == "1":
            return self.json(demo_status())
        exits = self.app.store.list_exits()
        traffic = self.app.store.traffic()
        items = []
        for e in exits:
            h = self.app.store.last_health(e["id"]) or {}
            t = traffic.get(e["id"], {})
            items.append({
                **{k: e[k] for k in ("id", "name", "kind", "endpoint", "socks_port",
                                     "weight", "enabled", "note", "created_at")},
                "health": {"ok": bool(h.get("ok")), "ts": h.get("ts"),
                           "latency_ms": h.get("latency_ms"),
                           "exit_ip": h.get("exit_ip"),
                           "country": h.get("country"),
                           "error": h.get("error") or ""},
                "breaker": self.app.breaker.get(e["id"]),
                "traffic": {"up": t.get("up_bytes", 0), "down": t.get("down_bytes", 0),
                            "conns": t.get("conns", 0), "failures": t.get("failures", 0)},
                "running": self.app.xray.alive(e["id"]) if e["kind"] in SUPPORTED else True,
            })
        ranked = self.app.selector.ranked()
        live = [r for r in ranked if r["score"] > 0]
        return self.json({
            "ok": True,
            "version": __version__,
            "uptime": int(time.time()) - self.app.started_at,
            "router": {"listen": self.app.router.listen, "port": self.app.router.port,
                       "connections": self.app.router.conn_count,
                       "sticky": self.app.router.sticky.size()},
            "exits": items,
            "active_exit": live[0]["id"] if live else None,
            "ranking": [{"id": r["id"], "score": r["score"],
                         "latency_ms": r["latency_ms"]} for r in ranked],
            "direct": getattr(self.app, "direct_probe", None),
        })

    def api_list_exits(self):
        return self.json({"ok": True, "items": self.app.store.list_exits()})

    def api_add_exit(self):
        b = self.body_json()
        name = str(b.get("name") or "").strip()
        link = str(b.get("link") or "").strip()
        endpoint = str(b.get("endpoint") or "").strip()
        kind = str(b.get("kind") or "").strip().lower()

        if not name:
            return self.err(400, "name is required")

        if link:
            try:
                parsed = parse_link(link)
            except Exception as ex:
                return self.err(400, f"cannot parse link: {ex}")
            kind = parsed["proto"]
            endpoint = f"{parsed['server']}:{parsed['port']}"
            if not name:
                name = parsed.get("name") or endpoint
        elif endpoint:
            if not kind:
                kind = "socks5"
            if ":" not in endpoint:
                return self.err(400, "endpoint must be host:port")
        else:
            return self.err(400, "either a share link or an endpoint is required")

        eid = self.app.store.add_exit(name, kind, endpoint=endpoint, link=link,
                                      weight=int(b.get("weight") or 100),
                                      note=str(b.get("note") or ""))
        if link:
            self.app.sync_xray()
        self.app.store.log(self.client_ip(), "exit-add", f"{eid} ({kind})")
        e = self.app.store.get_exit(eid)
        threading.Thread(target=self.app.probe_one, args=(eid,), daemon=True).start()
        return self.json({"ok": True, "exit": e})

    def api_delete_exit(self, eid):
        e = self.app.store.get_exit(eid)
        if not e:
            return self.err(404, "no such exit")
        self.app.xray.stop(e["id"])
        self.app.store.delete_exit(e["id"])
        self.app.store.log(self.client_ip(), "exit-delete", e["id"])
        return self.json({"ok": True})

    def api_exit_action(self, eid, action, q):
        e = self.app.store.get_exit(eid)
        if not e:
            return self.err(404, "no such exit")
        b = self.body_json()

        if action == "toggle":
            new = 0 if e.get("enabled") else 1
            self.app.store.update_exit(e["id"], enabled=new)
            if new:
                if e["kind"] in SUPPORTED:
                    self.app.xray.start(e["id"])
            else:
                self.app.xray.stop(e["id"])
            self.app.store.log(self.client_ip(), "exit-toggle", f"{e['id']}={new}")
            return self.json({"ok": True, "enabled": new})

        if action == "probe":
            return self.json({"ok": True, "result": self.app.probe_one(e["id"])})

        if action == "restart":
            if e["kind"] not in SUPPORTED:
                return self.err(400, "only xray-backed exits can be restarted")
            ok, msg = self.app.xray.start(e["id"])
            self.app.store.log(self.client_ip(), "exit-restart", f"{e['id']}: {msg}")
            return self.json({"ok": ok, "message": msg})

        if action == "weight":
            w = int(b.get("weight") or e.get("weight") or 100)
            self.app.store.update_exit(e["id"], weight=max(1, min(1000, w)))
            return self.json({"ok": True, "weight": w})

        if action == "reset-traffic":
            self.app.store.reset_traffic(e["id"])
            return self.json({"ok": True})

        return self.err(404, "unknown action")

    def api_set_rules(self):
        b = self.body_json()
        rules = b.get("rules")
        if not isinstance(rules, list):
            return self.err(400, "rules must be a list")
        for r in rules:
            if not isinstance(r, dict) or "match" not in r:
                return self.err(400, "each rule needs a match object")
        self.app.store.set_rules({"rules": rules})
        self.app.store.log(self.client_ip(), "rules-update", f"{len(rules)} rules")
        return self.json({"ok": True})

    def api_set_settings(self):
        b = self.body_json()
        allowed = {"sticky_ttl", "health_interval", "health_timeout",
                   "unhealthy_after", "router_listen", "router_socks_port"}
        changed = {}
        for k, v in b.items():
            if k in allowed:
                self.app.store.set_setting(k, v)
                changed[k] = v
        if "unhealthy_after" in changed:
            self.app.breaker.threshold = int(changed["unhealthy_after"])
        if "sticky_ttl" in changed:
            self.app.router.sticky.ttl = int(changed["sticky_ttl"])
        if "health_timeout" in changed:
            self.app.selector.timeout = float(changed["health_timeout"])
        self.app.store.log(self.client_ip(), "settings", json.dumps(changed))
        return self.json({"ok": True, "changed": changed})


def serve(db_path, xray_bin="/usr/local/bin/xray", listen="127.0.0.1", port=None):
    app = App(db_path, xray_bin=xray_bin, listen=listen)
    if port:
        app.port = int(port)

    if not app.has_password():
        pw = os.environ.get("EXITMESH_PASSWORD") or secrets.token_urlsafe(12)
        app.set_password(pw)
        print(f"[exitmesh] initial admin password: {pw}", flush=True)

    Handler.app = app
    httpd = ThreadingHTTPServer((listen, app.port), Handler)
    httpd.daemon_threads = True

    app.sync_xray()

    def worker():
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.create_task(app.router.start())
        loop.create_task(app.stats.run())
        loop.run_forever()

    threading.Thread(target=worker, daemon=True).start()

    def prober():
        interval = int(app.store.get_setting("health_interval", "60"))
        while True:
            try:
                app.probe_all()
                app.xray.ensure_running()
            except Exception:
                pass
            time.sleep(max(15, interval))

    threading.Thread(target=prober, daemon=True).start()
    print(f"[exitmesh] panel on http://{listen}:{app.port}  "
          f"socks router on {app.router.listen}:{app.router.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
        httpd.server_close()
