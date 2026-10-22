"""SQLite persistence for ExitMesh: exits, health, traffic, rules, audit."""

import json
import os
import re
import sqlite3
import threading
import time

# An exit id becomes a filename (`<id>.json` under the xray config dir), so it
# must never contain a path separator or a traversal sequence. Names are free
# text from the panel, so the id is derived defensively: keep [a-z0-9-_.], fold
# everything else to '-', and reject anything that still looks like a path.
_ID_SAFE = re.compile(r"[^a-z0-9._-]+")


def safe_exit_id(name, fallback="exit"):
    """Derive a filesystem-safe id from a user-supplied exit name.

    Without this, a name like `../../x` produced a config path outside the
    config directory, and since the service runs as root that is arbitrary
    file write. The id is also used as a URL path segment, so keep it to a
    conservative charset.
    """
    raw = str(name or "").strip().lower()
    slug = _ID_SAFE.sub("-", raw).strip("-._")
    slug = slug.replace("..", "-")[:48].strip("-._")
    if not slug:
        slug = fallback
    # Belt and braces: never hand back something with a separator or parent ref.
    if "/" in slug or "\\" in slug or slug in (".", ".."):
        slug = fallback
    return slug

SCHEMA = """
CREATE TABLE IF NOT EXISTS exits (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,          -- socks5 | http | vless | vmess | trojan | ss
    endpoint    TEXT NOT NULL,          -- host:port of the upstream, or '' for xray links
    link        TEXT DEFAULT '',        -- original share link (xray kinds)
    socks_port  INTEGER DEFAULT 0,      -- local socks port (xray kinds)
    weight      INTEGER DEFAULT 100,
    enabled     INTEGER DEFAULT 1,
    created_at  INTEGER NOT NULL,
    note        TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS health (
    exit_id     TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    ok          INTEGER NOT NULL,
    latency_ms  INTEGER,
    exit_ip     TEXT,
    country     TEXT,
    error       TEXT,
    PRIMARY KEY (exit_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_health_exit ON health(exit_id, ts DESC);

CREATE TABLE IF NOT EXISTS traffic (
    exit_id     TEXT PRIMARY KEY,
    up_bytes    INTEGER DEFAULT 0,
    down_bytes  INTEGER DEFAULT 0,
    conns       INTEGER DEFAULT 0,
    failures    INTEGER DEFAULT 0,
    updated_at  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    ts          INTEGER NOT NULL,
    actor       TEXT,
    action      TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);
"""

DEFAULT_SETTINGS = {
    "router_socks_port": 10800,
    "router_http_port": 10801,
    "router_listen": "127.0.0.1",
    "panel_port": 8099,
    "sticky_ttl": 900,
    "health_interval": 60,
    "health_timeout": 6,
    "unhealthy_after": 3,
    "rules": json.dumps({"rules": [{"match": {"default": True}, "exit": "auto"}]}),
}


class Store:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()
        for k, v in DEFAULT_SETTINGS.items():
            self.db.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES(?,?)", (k, v)
            )
        self.db.commit()

    # ---------------------------------------------------------------- exits
    def list_exits(self):
        with self._lock:
            rows = self.db.execute("SELECT * FROM exits ORDER BY name").fetchall()
        return [dict(r) for r in rows]

    def get_exit(self, name):
        with self._lock:
            r = self.db.execute(
                "SELECT * FROM exits WHERE id=? OR name=?", (name, name)
            ).fetchone()
        return dict(r) if r else None

    def add_exit(self, name, kind, endpoint="", link="", weight=100, note=""):
        eid = safe_exit_id(name)
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO exits(id,name,kind,endpoint,link,weight,"
                "enabled,created_at,note) VALUES(?,?,?,?,?,?,1,?,?)",
                (eid, name, kind, endpoint, link, int(weight), int(time.time()), note),
            )
            self.db.execute(
                "INSERT OR IGNORE INTO traffic(exit_id,updated_at) VALUES(?,?)",
                (eid, int(time.time())),
            )
            self.db.commit()
        return eid

    def update_exit(self, eid, **fields):
        allowed = {"name", "kind", "endpoint", "link", "socks_port",
                   "weight", "enabled", "note"}
        sets, vals = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                vals.append(v)
        if not sets:
            return False
        vals.append(eid)
        with self._lock:
            self.db.execute(f"UPDATE exits SET {','.join(sets)} WHERE id=?", vals)
            self.db.commit()
        return True

    def delete_exit(self, eid):
        with self._lock:
            self.db.execute("DELETE FROM exits WHERE id=?", (eid,))
            self.db.execute("DELETE FROM health WHERE exit_id=?", (eid,))
            self.db.execute("DELETE FROM traffic WHERE exit_id=?", (eid,))
            self.db.commit()

    # --------------------------------------------------------------- health
    def record_health(self, eid, ok, latency=None, exit_ip=None, country=None, error=""):
        ts = int(time.time())
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO health(exit_id,ts,ok,latency_ms,exit_ip,"
                "country,error) VALUES(?,?,?,?,?,?,?)",
                (eid, ts, 1 if ok else 0, latency, exit_ip, country, error[:200]),
            )
            # keep the table small: drop samples older than 7 days
            self.db.execute("DELETE FROM health WHERE ts < ?", (ts - 7 * 86400,))
            self.db.commit()

    def last_health(self, eid):
        with self._lock:
            r = self.db.execute(
                "SELECT * FROM health WHERE exit_id=? ORDER BY ts DESC LIMIT 1", (eid,)
            ).fetchone()
        return dict(r) if r else None

    def health_series(self, eid, limit=60):
        with self._lock:
            rows = self.db.execute(
                "SELECT ts,ok,latency_ms FROM health WHERE exit_id=? "
                "ORDER BY ts DESC LIMIT ?", (eid, limit)
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def consecutive_failures(self, eid):
        with self._lock:
            rows = self.db.execute(
                "SELECT ok FROM health WHERE exit_id=? ORDER BY ts DESC LIMIT 10", (eid,)
            ).fetchall()
        n = 0
        for r in rows:
            if r["ok"]:
                break
            n += 1
        return n

    # -------------------------------------------------------------- traffic
    def add_traffic(self, eid, up=0, down=0, conns=0, failures=0):
        with self._lock:
            self.db.execute(
                "INSERT INTO traffic(exit_id,up_bytes,down_bytes,conns,failures,updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(exit_id) DO UPDATE SET "
                "up_bytes=up_bytes+excluded.up_bytes, "
                "down_bytes=down_bytes+excluded.down_bytes, "
                "conns=conns+excluded.conns, "
                "failures=failures+excluded.failures, "
                "updated_at=excluded.updated_at",
                (eid, up, down, conns, failures, int(time.time())),
            )
            self.db.commit()

    def traffic(self):
        with self._lock:
            rows = self.db.execute("SELECT * FROM traffic").fetchall()
        return {r["exit_id"]: dict(r) for r in rows}

    def reset_traffic(self, eid=None):
        with self._lock:
            if eid:
                self.db.execute(
                    "UPDATE traffic SET up_bytes=0,down_bytes=0,conns=0,failures=0 "
                    "WHERE exit_id=?", (eid,))
            else:
                self.db.execute(
                    "UPDATE traffic SET up_bytes=0,down_bytes=0,conns=0,failures=0")
            self.db.commit()

    # ------------------------------------------------------------- settings
    def get_setting(self, key, default=None):
        with self._lock:
            r = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    def set_setting(self, key, value):
        with self._lock:
            self.db.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )
            self.db.commit()

    def all_settings(self):
        with self._lock:
            rows = self.db.execute("SELECT key,value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def rules(self):
        try:
            return json.loads(self.get_setting("rules") or '{"rules":[]}')
        except Exception:
            return {"rules": [{"match": {"default": True}, "exit": "auto"}]}

    def set_rules(self, rules):
        self.set_setting("rules", json.dumps(rules, ensure_ascii=False))

    # ---------------------------------------------------------------- audit
    def log(self, actor, action, detail=""):
        with self._lock:
            self.db.execute(
                "INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
                (int(time.time()), actor, action, str(detail)[:500]),
            )
            self.db.execute("DELETE FROM audit WHERE ts < ?",
                            (int(time.time()) - 30 * 86400,))
            self.db.commit()

    def recent_audit(self, limit=100):
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
