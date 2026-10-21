"""Health probes: latency, real exit IP, country — through each exit.

Everything here is stdlib and synchronous on purpose: probes run in a worker
thread, so blocking sockets keep the code short and predictable.
"""

import json
import socket
import ssl
import struct
import time

IP_ENDPOINTS = [
    ("https://api.ipify.org", 443),
    ("https://checkip.amazonaws.com", 443),
    ("http://ifconfig.me/ip", 80),
]

GEO_ENDPOINT = "http://ip-api.com/json/{ip}?fields=status,country,countryCode"


class ProbeError(Exception):
    pass


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProbeError("connection closed")
        buf += chunk
    return buf


def socks5_connect(proxy_host, proxy_port, host, port, timeout=8):
    """Open a TCP stream to host:port through a SOCKS5 proxy. Returns the socket."""
    s = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        resp = _recv_exact(s, 2)
        if resp[0] != 5 or resp[1] != 0:
            raise ProbeError("socks auth rejected")
        try:
            socket.inet_aton(host)
            req = b"\x05\x01\x00\x01" + socket.inet_aton(host)
        except OSError:
            hb = host.encode("idna")
            req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
        req += struct.pack("!H", port)
        s.sendall(req)
        head = _recv_exact(s, 4)
        if head[1] != 0:
            raise ProbeError(f"socks connect failed (rep={head[1]})")
        atyp = head[3]
        if atyp == 1:
            _recv_exact(s, 4)
        elif atyp == 4:
            _recv_exact(s, 16)
        elif atyp == 3:
            ln = _recv_exact(s, 1)[0]
            _recv_exact(s, ln)
        _recv_exact(s, 2)
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise


def _http_get(sock, host, path="/", tls=False, timeout=8):
    s = sock
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(sock, server_hostname=host)
        s.settimeout(timeout)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           "User-Agent: exitmesh-probe/1.0\r\nAccept: */*\r\n"
           "Connection: close\r\n\r\n")
    s.sendall(req.encode())
    chunks = []
    total = 0
    while total < 65536:
        try:
            b = s.recv(8192)
        except socket.timeout:
            break
        if not b:
            break
        chunks.append(b)
        total += len(b)
    s.close()
    raw = b"".join(chunks)
    if b"\r\n\r\n" not in raw:
        raise ProbeError("no http response")
    head, body = raw.split(b"\r\n\r\n", 1)
    if b" 200 " not in head.split(b"\r\n")[0]:
        raise ProbeError("non-200 response")
    if b"chunked" in head.lower():
        out, rest = b"", body
        while rest:
            ln, _, rest = rest.partition(b"\r\n")
            try:
                n = int(ln.split(b";")[0], 16)
            except ValueError:
                break
            if n == 0:
                break
            out += rest[:n]
            rest = rest[n + 2:]
        body = out
    return body.decode("utf-8", "replace").strip()


def _ip_lookup(connect):
    """connect(host, port, tls) -> body string"""
    last = None
    for url, port in IP_ENDPOINTS:
        tls = url.startswith("https")
        host = url.split("://", 1)[1].split("/")[0]
        path = "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
        try:
            body = connect(host, port, tls, path)
            ip = body.split()[0] if body else ""
            if _looks_like_ip(ip):
                return ip
        except Exception as e:
            last = e
    raise ProbeError(f"ip lookup failed: {last}")


def _looks_like_ip(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, s)
            return True
        except OSError:
            return False


def geo(ip, timeout=6):
    """Country lookup. Returns (country_name, country_code) or (None, None)."""
    try:
        s = socket.create_connection(("ip-api.com", 80), timeout=timeout)
        s.settimeout(timeout)
        path = f"/json/{ip}?fields=status,country,countryCode"
        body = _http_get(s, "ip-api.com", path)
        d = json.loads(body)
        if d.get("status") == "success":
            return d.get("country"), d.get("countryCode")
    except Exception:
        pass
    return None, None


def probe_via_socks(proxy_host, proxy_port, timeout=8):
    """Latency + exit IP for a local SOCKS5 listener."""
    t0 = time.time()
    s = socks5_connect(proxy_host, proxy_port, "api.ipify.org", 443, timeout=timeout)
    latency = int((time.time() - t0) * 1000)

    def connect(host, port, tls, path):
        sock = s if host == "api.ipify.org" else socks5_connect(
            proxy_host, proxy_port, host, port, timeout=timeout)
        return _http_get(sock, host, path, tls=tls, timeout=timeout)

    try:
        ip = _ip_lookup(connect)
    finally:
        try:
            s.close()
        except Exception:
            pass
    country, cc = geo(ip)
    return {"ok": True, "latency_ms": latency, "exit_ip": ip,
            "country": country, "country_code": cc, "error": ""}


def probe_direct(timeout=6):
    t0 = time.time()

    def connect(host, port, tls, path):
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return _http_get(sock, host, path, tls=tls, timeout=timeout)

    ip = _ip_lookup(connect)
    latency = int((time.time() - t0) * 1000)
    country, cc = geo(ip)
    return {"ok": True, "latency_ms": latency, "exit_ip": ip,
            "country": country, "country_code": cc, "error": ""}


def probe_tcp(host, port, timeout=4):
    t0 = time.time()
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close()
        return {"ok": True, "latency_ms": int((time.time() - t0) * 1000), "error": ""}
    except Exception as e:
        return {"ok": False, "latency_ms": None, "error": str(e)[:120]}
