"""Parse share links and turn them into Xray inbound->outbound configs.

Supported: vless://, vmess://, trojan://, ss://  (the same set 3x-ui exports).
Each exit becomes a small Xray instance listening on 127.0.0.1:<socks_port>
with a SOCKS inbound, so the router can treat it like any other exit.
"""

import base64
import json
import os
import re
import subprocess
import time
import urllib.parse

SUPPORTED = ("vless", "vmess", "trojan", "ss")


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def parse_link(link):
    """Return a normalized dict, or raise ValueError with a readable reason."""
    link = link.strip()
    if "://" not in link:
        raise ValueError("not a share link (missing scheme)")
    scheme = link.split("://", 1)[0].lower()
    if scheme not in SUPPORTED:
        raise ValueError(f"unsupported scheme: {scheme}")

    if scheme == "vmess":
        return _parse_vmess(link)
    if scheme == "ss":
        return _parse_ss(link)

    u = urllib.parse.urlsplit(link)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
    host = u.hostname or ""
    port = u.port or 443
    if not host:
        raise ValueError("missing host")

    name = urllib.parse.unquote(u.fragment or f"{scheme}-{host}")

    if scheme == "vless":
        out = {
            "proto": "vless",
            "name": name,
            "server": host,
            "port": port,
            "id": urllib.parse.unquote(u.username or ""),
            "flow": q.get("flow", ""),
            "encryption": q.get("encryption", "none"),
            "security": q.get("security", "none"),
            "sni": q.get("sni", q.get("peer", "")),
            "fp": q.get("fp", ""),
            "alpn": q.get("alpn", ""),
            "pbk": q.get("pbk", ""),
            "sid": q.get("sid", ""),
            "spx": q.get("spx", "/"),
            "type": q.get("type", "tcp"),
            "path": q.get("path", ""),
            "host": q.get("host", ""),
            "serviceName": q.get("serviceName", ""),
            "mode": q.get("mode", ""),
            "headerType": q.get("headerType", ""),
        }
        if not out["id"]:
            raise ValueError("vless link has no UUID")
        return out

    if scheme == "trojan":
        out = {
            "proto": "trojan",
            "name": name,
            "server": host,
            "port": port,
            "password": urllib.parse.unquote(u.username or ""),
            "security": q.get("security", "tls"),
            "sni": q.get("sni", q.get("peer", "")),
            "fp": q.get("fp", ""),
            "alpn": q.get("alpn", ""),
            "type": q.get("type", "tcp"),
            "path": q.get("path", ""),
            "host": q.get("host", ""),
            "serviceName": q.get("serviceName", ""),
        }
        if not out["password"]:
            raise ValueError("trojan link has no password")
        return out

    raise ValueError("unreachable")


def _parse_vmess(link):
    body = link.split("://", 1)[1]
    raw = b64d(urllib.parse.unquote(body)).decode("utf-8", "replace")
    j = json.loads(raw)
    return {
        "proto": "vmess",
        "name": j.get("ps") or f"vmess-{j.get('add')}",
        "server": j.get("add", ""),
        "port": int(j.get("port") or 443),
        "id": j.get("id", ""),
        "aid": int(j.get("aid") or 0),
        "scy": j.get("scy") or "auto",
        "net": j.get("net") or "tcp",
        "type": j.get("type") or "none",
        "host": j.get("host", ""),
        "path": j.get("path", ""),
        "tls": j.get("tls", ""),
        "sni": j.get("sni", "") or j.get("host", ""),
        "alpn": j.get("alpn", ""),
        "fp": j.get("fp", ""),
    }


def _parse_ss(link):
    body = link.split("://", 1)[1]
    name = ""
    if "#" in body:
        body, name = body.split("#", 1)
        name = urllib.parse.unquote(name)
    body = body.split("?", 1)[0]
    if "@" not in body:
        body = b64d(urllib.parse.unquote(body)).decode()
    userinfo, hostport = body.rsplit("@", 1)
    try:
        method, password = b64d(urllib.parse.unquote(userinfo)).decode().split(":", 1)
    except Exception:
        method, password = urllib.parse.unquote(userinfo).split(":", 1)
    host, _, port = hostport.rpartition(":")
    return {
        "proto": "ss",
        "name": name or f"ss-{host}",
        "server": host.strip("[]"),
        "port": int(port),
        "method": method,
        "password": password,
    }


# --------------------------------------------------------------- to xray json
def _stream_settings(p):
    net = (p.get("type") or p.get("net") or "tcp").lower()
    sec = (p.get("security") or p.get("tls") or "none").lower()
    if sec == "reality":
        sec = "reality"
    elif sec in ("tls", "xtls"):
        sec = "tls"
    else:
        sec = "none"

    ss = {"network": net}

    if net in ("tcp", "raw"):
        ss["network"] = "tcp"
        if p.get("headerType") == "http":
            ss["tcpSettings"] = {"header": {"type": "http",
                                            "request": {"path": [p.get("path") or "/"]}}}
    elif net in ("ws", "websocket"):
        ss["network"] = "ws"
        ss["wsSettings"] = {"path": p.get("path") or "/",
                            "headers": {"Host": p.get("host") or p.get("sni") or ""}}
    elif net in ("grpc", "gun"):
        ss["network"] = "grpc"
        ss["grpcSettings"] = {"serviceName": p.get("serviceName") or ""}
    elif net in ("h2", "http"):
        ss["network"] = "h2"
        ss["httpSettings"] = {"path": p.get("path") or "/",
                              "host": [p.get("host") or ""]}
    elif net in ("xhttp", "splithttp"):
        ss["network"] = "xhttp"
        ss["xhttpSettings"] = {"path": p.get("path") or "/",
                               "host": p.get("host") or "",
                               "mode": p.get("mode") or "auto"}
    else:
        ss["network"] = "tcp"

    if sec == "tls":
        t = {"serverName": p.get("sni") or p.get("host") or p.get("server"),
             "allowInsecure": False}
        if p.get("alpn"):
            t["alpn"] = [a for a in p["alpn"].split(",") if a]
        if p.get("fp"):
            t["fingerprint"] = p["fp"]
        ss["security"] = "tls"
        ss["tlsSettings"] = t
    elif sec == "reality":
        r = {"serverName": p.get("sni") or p.get("host") or "",
             "fingerprint": p.get("fp") or "chrome",
             "publicKey": p.get("pbk") or "",
             "shortId": p.get("sid") or "",
             "spiderX": p.get("spx") or "/"}
        ss["security"] = "reality"
        ss["realitySettings"] = r
    else:
        ss["security"] = "none"
    return ss


def to_xray_outbound(p):
    proto = p["proto"]
    if proto == "vless":
        user = {"id": p["id"], "encryption": p.get("encryption") or "none"}
        if p.get("flow"):
            user["flow"] = p["flow"]
        return {"tag": "proxy", "protocol": "vless",
                "settings": {"vnext": [{"address": p["server"], "port": int(p["port"]),
                                        "users": [user]}]},
                "streamSettings": _stream_settings(p)}
    if proto == "vmess":
        return {"tag": "proxy", "protocol": "vmess",
                "settings": {"vnext": [{"address": p["server"], "port": int(p["port"]),
                                        "users": [{"id": p["id"], "alterId": p.get("aid", 0),
                                                   "security": p.get("scy") or "auto"}]}]},
                "streamSettings": _stream_settings(
                    {**p, "type": p.get("net"), "security": p.get("tls") or "none"})}
    if proto == "trojan":
        return {"tag": "proxy", "protocol": "trojan",
                "settings": {"servers": [{"address": p["server"], "port": int(p["port"]),
                                          "password": p["password"]}]},
                "streamSettings": _stream_settings(p)}
    if proto == "ss":
        return {"tag": "proxy", "protocol": "shadowsocks",
                "settings": {"servers": [{"address": p["server"], "port": int(p["port"]),
                                          "method": p["method"],
                                          "password": p["password"]}]}}
    raise ValueError(f"cannot build outbound for {proto}")


def build_config(parsed, socks_port, listen="127.0.0.1", log_level="warning"):
    return {
        "log": {"loglevel": log_level, "access": "none",
                "error": f"/tmp/exitmesh-xray-{socks_port}.log"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": listen,
            "port": int(socks_port),
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": listen},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }],
        "outbounds": [
            to_xray_outbound(parsed),
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


# ------------------------------------------------------------------ supervisor
class XraySupervisor:
    """Spawns one xray process per exit and keeps it alive."""

    def __init__(self, binary, conf_dir, store):
        self.binary = binary
        self.conf_dir = conf_dir
        self.store = store
        self.procs = {}       # eid -> Popen
        os.makedirs(conf_dir, exist_ok=True)

    def conf_path(self, eid):
        return os.path.join(self.conf_dir, f"{eid}.json")

    def write_config(self, eid, parsed, socks_port):
        cfg = build_config(parsed, socks_port)
        path = self.conf_path(eid)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        return path

    def validate(self, path):
        try:
            r = subprocess.run([self.binary, "run", "-test", "-c", path],
                               capture_output=True, text=True, timeout=15)
            return r.returncode == 0, (r.stderr or r.stdout)[-400:]
        except FileNotFoundError:
            return False, f"xray binary not found: {self.binary}"
        except subprocess.TimeoutExpired:
            return False, "validation timed out"

    def start(self, eid):
        path = self.conf_path(eid)
        if not os.path.exists(path):
            return False, "config missing"
        self.stop(eid)
        try:
            proc = subprocess.Popen(
                [self.binary, "run", "-c", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except FileNotFoundError:
            return False, f"xray binary not found: {self.binary}"
        self.procs[eid] = proc
        time.sleep(0.4)
        if proc.poll() is not None:
            return False, f"xray exited immediately (code {proc.returncode})"
        return True, f"pid {proc.pid}"

    def stop(self, eid):
        proc = self.procs.pop(eid, None)
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def stop_all(self):
        for eid in list(self.procs):
            self.stop(eid)

    def alive(self, eid):
        p = self.procs.get(eid)
        return bool(p and p.poll() is None)

    def ensure_running(self):
        """Called by the watchdog: restart anything enabled whose process died."""
        restarted = []
        for e in self.store.list_exits():
            if not e.get("enabled"):
                continue
            if e["kind"] in SUPPORTED and e.get("link"):
                if not self.alive(e["id"]) and os.path.exists(self.conf_path(e["id"])):
                    ok, _ = self.start(e["id"])
                    if ok:
                        restarted.append(e["id"])
        return restarted
