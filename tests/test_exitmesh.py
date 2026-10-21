"""Tests for parsing, selection, storage and the live SOCKS router.

Run:  python3 -m pytest tests/ -q      (or: python3 tests/test_exitmesh.py)
"""

import asyncio
import base64
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from exitmesh.selector import Breaker, Selector          # noqa: E402
from exitmesh.socks import Router, StatsBuffer           # noqa: E402
from exitmesh.store import Store                         # noqa: E402
from exitmesh.xray import build_config, parse_link, to_xray_outbound  # noqa: E402

from fixture_socks import FixtureSocks                   # noqa: E402


# --------------------------------------------------------------------- links
VLESS = ("vless://11111111-2222-3333-4444-555555555555@example.com:443"
         "?type=tcp&security=reality&pbk=PUBKEY&sid=ab12&fp=chrome"
         "&sni=www.microsoft.com&flow=xtls-rprx-vision#tokyo-1")


def test_parse_vless():
    p = parse_link(VLESS)
    assert p["proto"] == "vless"
    assert p["server"] == "example.com"
    assert p["port"] == 443
    assert p["id"].startswith("11111111")
    assert p["security"] == "reality"
    assert p["pbk"] == "PUBKEY"
    assert p["flow"] == "xtls-rprx-vision"
    assert p["name"] == "tokyo-1"


def test_parse_vmess_roundtrip():
    inner = {"v": "2", "ps": "ams-2", "add": "1.2.3.4", "port": "8443",
             "id": "aaaa-bbbb", "aid": "0", "net": "ws", "type": "none",
             "host": "cdn.example.com", "path": "/ray", "tls": "tls",
             "sni": "cdn.example.com"}
    link = "vmess://" + base64.b64encode(json.dumps(inner).encode()).decode()
    p = parse_link(link)
    assert p["proto"] == "vmess"
    assert p["name"] == "ams-2"
    assert p["port"] == 8443
    assert p["net"] == "ws"
    assert p["path"] == "/ray"


def test_parse_trojan():
    p = parse_link("trojan://secret@t.example.com:8443?sni=t.example.com&type=ws"
                   "&path=%2Fws#fra-1")
    assert p["proto"] == "trojan"
    assert p["password"] == "secret"
    assert p["path"] == "/ws"


def test_parse_ss():
    ui = base64.b64encode(b"aes-256-gcm:pass123").decode()
    p = parse_link(f"ss://{ui}@1.1.1.1:8388#hk-1")
    assert p["proto"] == "ss"
    assert p["method"] == "aes-256-gcm"
    assert p["password"] == "pass123"
    assert p["port"] == 8388


def test_reject_unknown_scheme():
    try:
        parse_link("hysteria2://x@y:1")
    except ValueError as e:
        assert "unsupported" in str(e)
    else:
        raise AssertionError("should have raised")


def test_xray_config_shape():
    p = parse_link(VLESS)
    cfg = build_config(p, 20001)
    assert cfg["inbounds"][0]["port"] == 20001
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"
    ob = cfg["outbounds"][0]
    assert ob["protocol"] == "vless"
    assert ob["streamSettings"]["security"] == "reality"
    assert ob["streamSettings"]["realitySettings"]["publicKey"] == "PUBKEY"
    assert ob["streamSettings"]["network"] == "tcp"


def test_xray_ws_and_grpc():
    ws = to_xray_outbound({"proto": "vless", "server": "h", "port": 443,
                           "id": "u", "type": "ws", "path": "/p", "host": "cdn",
                           "security": "tls", "sni": "cdn"})
    assert ws["streamSettings"]["network"] == "ws"
    assert ws["streamSettings"]["wsSettings"]["path"] == "/p"

    gr = to_xray_outbound({"proto": "vless", "server": "h", "port": 443,
                           "id": "u", "type": "grpc", "serviceName": "svc",
                           "security": "tls", "sni": "cdn"})
    assert gr["streamSettings"]["grpcSettings"]["serviceName"] == "svc"


# -------------------------------------------------------------------- store
def test_store_crud_and_traffic():
    with tempfile.TemporaryDirectory() as d:
        s = Store(os.path.join(d, "t.db"))
        eid = s.add_exit("Tokyo 1", "vless", endpoint="example.com:443", weight=80)
        assert eid == "tokyo-1"
        assert len(s.list_exits()) == 1

        s.record_health(eid, True, 120, "1.2.3.4", "Japan")
        h = s.last_health(eid)
        assert h["ok"] == 1 and h["latency_ms"] == 120

        s.add_traffic(eid, up=100, down=200, conns=1)
        s.add_traffic(eid, up=50, down=25, conns=2)
        t = s.traffic()[eid]
        assert t["up_bytes"] == 150 and t["down_bytes"] == 225 and t["conns"] == 3

        s.update_exit(eid, weight=200, enabled=0)
        assert s.get_exit(eid)["weight"] == 200
        s.delete_exit(eid)
        assert s.list_exits() == []


def test_consecutive_failures():
    with tempfile.TemporaryDirectory() as d:
        s = Store(os.path.join(d, "t.db"))
        eid = s.add_exit("x", "socks5", endpoint="1.1.1.1:1080")
        for _ in range(3):
            s.record_health(eid, False, error="refused")
            time.sleep(1.05)      # ts is second-granularity
        assert s.consecutive_failures(eid) == 3
        s.record_health(eid, True, 50)
        assert s.consecutive_failures(eid) == 0


# ----------------------------------------------------------------- selector
def test_ranking_prefers_healthy_and_fast():
    with tempfile.TemporaryDirectory() as d:
        s = Store(os.path.join(d, "t.db"))
        fast = s.add_exit("fast", "socks5", endpoint="1.1.1.1:1080", weight=100)
        slow = s.add_exit("slow", "socks5", endpoint="2.2.2.2:1080", weight=100)
        dead = s.add_exit("dead", "socks5", endpoint="3.3.3.3:1080", weight=500)
        s.record_health(fast, True, 40, "1.1.1.1")
        s.record_health(slow, True, 600, "2.2.2.2")
        for _ in range(3):
            s.record_health(dead, False, error="timeout")
            time.sleep(1.05)

        sel = Selector(s)
        for _ in range(3):
            sel.breaker.record(dead, False)
        ranked = sel.ranked()
        assert ranked[0]["id"] == fast, ranked
        assert ranked[-1]["id"] == dead


def test_rules_domain_match_and_block():
    with tempfile.TemporaryDirectory() as d:
        s = Store(os.path.join(d, "t.db"))
        a = s.add_exit("a", "socks5", endpoint="1.1.1.1:1080")
        b = s.add_exit("b", "socks5", endpoint="2.2.2.2:1080")
        s.record_health(a, True, 20, "1.1.1.1")
        s.record_health(b, True, 20, "2.2.2.2")
        s.set_rules({"rules": [
            {"match": {"domain": "blocked.example"}, "exit": "block"},
            {"match": {"domain": "only.b.example"}, "exit": b},
            {"match": {"default": True}, "exit": "auto"},
        ]})
        sel = Selector(s)
        assert sel.pick(("127.0.0.1", 1), "blocked.example", 443) is None
        hit = sel.pick(("127.0.0.1", 1), "sub.only.b.example", 443)
        assert hit["id"] == b
        auto = sel.pick(("127.0.0.1", 1), "google.com", 443)
        assert auto["id"] in (a, b)


def test_breaker_opens_and_recovers():
    br = Breaker(threshold=2)
    br.record("x", False)
    assert not br.is_open("x")
    br.record("x", False)
    assert br.is_open("x")
    assert br.factor("x") == 0.0
    br.record("x", True, 90)
    assert not br.is_open("x")
    assert br.factor("x") == 1.0


# ------------------------------------------------------------ live router E2E
def _socks_request(port, host, dport, payload=b"PING\n", timeout=6):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    hb = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", dport))
    head = s.recv(4)
    assert head[1] == 0, f"socks connect failed rep={head[1]}"
    atyp = head[3]
    if atyp == 1:
        s.recv(4)
    elif atyp == 3:
        s.recv(s.recv(1)[0])
    s.recv(2)
    s.sendall(payload)
    data = s.recv(4096)
    s.close()
    return data


class EchoServer:
    """Tiny TCP echo server so the router can be tested without the internet."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(c,), daemon=True).start()

    def _echo(self, c):
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(d)
        except Exception:
            pass
        finally:
            c.close()

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except Exception:
            pass


def test_router_end_to_end():
    echo = EchoServer()
    fixture = FixtureSocks()

    with tempfile.TemporaryDirectory() as d:
        store = Store(os.path.join(d, "t.db"))
        loop = asyncio.new_event_loop()
        port = loop.run_until_complete(fixture.start())

        store.add_exit("fixture", "socks5", endpoint=f"127.0.0.1:{port}")
        store.record_health("fixture", True, 12, "127.0.0.1")

        sel = Selector(store)
        stats = StatsBuffer(store, flush_every=1)
        router = Router(store, sel, port=0, stats=stats)
        srv = loop.run_until_complete(router.start())
        rport = srv.sockets[0].getsockname()[1]

        t = threading.Thread(target=loop.run_forever, daemon=True)
        t.start()

        try:
            out = _socks_request(rport, "127.0.0.1", echo.port, b"hello-mesh\n")
            assert out == b"hello-mesh\n", out
            assert fixture.counter["n"] >= 1
            time.sleep(0.5)          # let the pump finish counting
            stats.flush()
            tr = store.traffic()["fixture"]
            assert tr["conns"] >= 1, tr
            assert tr["up_bytes"] >= 11, tr
        finally:
            loop.call_soon_threadsafe(loop.stop)
            time.sleep(0.2)
            echo.close()

    assert True


def test_router_fails_over_when_first_exit_dead():
    echo = EchoServer()
    good = FixtureSocks()

    with tempfile.TemporaryDirectory() as d:
        store = Store(os.path.join(d, "t.db"))
        loop = asyncio.new_event_loop()
        gport = loop.run_until_complete(good.start())

        # dead exit has a much higher weight so it is ranked first
        store.add_exit("dead", "socks5", endpoint="127.0.0.1:1", weight=999)
        store.add_exit("good", "socks5", endpoint=f"127.0.0.1:{gport}", weight=10)
        store.record_health("dead", True, 1, "9.9.9.9")
        store.record_health("good", True, 300, "127.0.0.1")

        sel = Selector(store)
        router = Router(store, sel, port=0, stats=StatsBuffer(store))
        srv = loop.run_until_complete(router.start())
        rport = srv.sockets[0].getsockname()[1]

        threading.Thread(target=loop.run_forever, daemon=True).start()
        try:
            out = _socks_request(rport, "127.0.0.1", echo.port, b"failover\n")
            assert out == b"failover\n", out
            assert good.counter["n"] >= 1
        finally:
            loop.call_soon_threadsafe(loop.stop)
            time.sleep(0.2)
            echo.close()

    assert True


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    ok = fail = 0
    for name, fn in fns:
        try:
            fn()
            print(f"  PASS  {name}")
            ok += 1
        except Exception as e:
            print(f"  FAIL  {name}: {type(e).__name__}: {e}")
            fail += 1
    print(f"\n{ok} passed, {fail} failed")
    sys.exit(1 if fail else 0)
