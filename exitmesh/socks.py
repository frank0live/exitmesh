"""SOCKS5 router: one stable local port in front of N upstream exits.

Features that make this more than a port-forwarder:
  * health-aware selection (latency + failure penalty + weight)
  * sticky sessions per source address (same client keeps the same exit)
  * per-exit byte counters
  * automatic failover: if the chosen exit refuses, try the next best one
"""

import asyncio
import hashlib
import ipaddress
import socket
import struct
import time

SOCKS_VERSION = 5

AUTH_NONE = 0x00
AUTH_NO_ACCEPTABLE = 0xFF

CMD_CONNECT = 0x01

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_OK = 0x00
REP_GENERAL_FAILURE = 0x01
REP_HOST_UNREACHABLE = 0x04
REP_CONN_REFUSED = 0x05
REP_CMD_UNSUPPORTED = 0x07
REP_ATYP_UNSUPPORTED = 0x08


class SocksError(Exception):
    pass


async def read_exact(reader, n):
    data = await reader.readexactly(n)
    return data


async def read_address(reader, atyp):
    if atyp == ATYP_IPV4:
        host = socket.inet_ntoa(await read_exact(reader, 4))
    elif atyp == ATYP_IPV6:
        raw = await read_exact(reader, 16)
        host = str(ipaddress.IPv6Address(raw))
    elif atyp == ATYP_DOMAIN:
        ln = (await read_exact(reader, 1))[0]
        raw = await read_exact(reader, ln)
        try:
            host = raw.decode("idna")
        except (UnicodeError, ValueError):
            host = raw.decode("utf-8", "replace")
    else:
        raise SocksError(REP_ATYP_UNSUPPORTED)
    port = struct.unpack("!H", await read_exact(reader, 2))[0]
    return host, port


def build_reply(rep, host="0.0.0.0", port=0):
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            return b"\x05" + bytes([rep, 0x00, ATYP_IPV4]) + ip.packed + struct.pack("!H", port)
        return b"\x05" + bytes([rep, 0x00, ATYP_IPV6]) + ip.packed + struct.pack("!H", port)
    except ValueError:
        return b"\x05" + bytes([rep, 0x00, ATYP_IPV4]) + b"\x00\x00\x00\x00" + struct.pack("!H", 0)


async def socks5_handshake(reader, writer, timeout=15):
    """Server side of a SOCKS5 CONNECT. Returns (host, port)."""
    ver, nmethods = await asyncio.wait_for(read_exact(reader, 2), timeout)
    if ver != SOCKS_VERSION:
        raise SocksError(REP_GENERAL_FAILURE)
    methods = await read_exact(reader, nmethods)
    if AUTH_NONE not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        raise SocksError(REP_GENERAL_FAILURE)
    writer.write(b"\x05\x00")
    await writer.drain()

    ver, cmd, _rsv, atyp = await asyncio.wait_for(read_exact(reader, 4), timeout)
    if ver != SOCKS_VERSION:
        raise SocksError(REP_GENERAL_FAILURE)
    if cmd != CMD_CONNECT:
        writer.write(build_reply(REP_CMD_UNSUPPORTED))
        await writer.drain()
        raise SocksError(REP_CMD_UNSUPPORTED)
    host, port = await read_address(reader, atyp)
    return host, port


async def open_via_socks5(proxy_host, proxy_port, host, port, timeout=15):
    """Client side: CONNECT through an upstream SOCKS5 proxy."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port), timeout
    )
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await asyncio.wait_for(read_exact(reader, 2), timeout)
    if resp[0] != SOCKS_VERSION or resp[1] != 0x00:
        writer.close()
        raise SocksError(REP_GENERAL_FAILURE)

    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            req = b"\x05\x01\x00" + bytes([ATYP_IPV4]) + ip.packed
        else:
            req = b"\x05\x01\x00" + bytes([ATYP_IPV6]) + ip.packed
    except ValueError:
        hb = host.encode("idna")
        req = b"\x05\x01\x00" + bytes([ATYP_DOMAIN, len(hb)]) + hb
    req += struct.pack("!H", port)
    writer.write(req)
    await writer.drain()

    _ver, rep, _rsv, atyp = await asyncio.wait_for(read_exact(reader, 4), timeout)
    if rep != REP_OK:
        writer.close()
        raise SocksError(rep)
    await read_address(reader, atyp)  # bound address, ignored
    return reader, writer


class StickyTable:
    """Keeps a client pinned to one exit for `ttl` seconds."""

    def __init__(self, ttl=900):
        self.ttl = ttl
        self._map = {}

    def key(self, peer):
        host = peer[0] if isinstance(peer, tuple) else str(peer)
        return hashlib.sha1(host.encode()).hexdigest()[:16]

    def get(self, peer):
        k = self.key(peer)
        item = self._map.get(k)
        if not item:
            return None
        eid, exp = item
        if exp < time.time():
            self._map.pop(k, None)
            return None
        return eid

    def set(self, peer, eid):
        self._map[self.key(peer)] = (eid, time.time() + self.ttl)

    def clear(self):
        self._map.clear()

    def size(self):
        return len(self._map)


class Router:
    """The public SOCKS5 endpoint. Delegates exit choice to `selector`."""

    def __init__(self, store, selector, listen="127.0.0.1", port=10800,
                 sticky_ttl=900, stats=None):
        self.store = store
        self.selector = selector
        self.listen = listen
        self.port = port
        self.sticky = StickyTable(sticky_ttl)
        self.stats = stats
        self.server = None
        self.conn_count = 0

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle, self.listen, self.port, backlog=512
        )
        return self.server

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.conn_count += 1
        up = down = 0
        chosen = None
        try:
            host, port = await socks5_handshake(reader, writer)
            chosen = self.selector.pick(peer, host, port, sticky=self.sticky)

            if not chosen:
                writer.write(build_reply(REP_HOST_UNREACHABLE))
                await writer.drain()
                return

            # try the chosen exit, then fall back down the ranking
            candidates = [chosen] + [
                e for e in self.selector.ranked()
                if e["id"] != chosen["id"]
            ]
            upstream = None
            last_rep = REP_CONN_REFUSED
            for cand in candidates[:4]:
                try:
                    upstream = await self._connect(cand, host, port)
                    chosen = cand
                    break
                except SocksError as e:
                    last_rep = e.args[0] if e.args else REP_CONN_REFUSED
                    if self.stats:
                        self.stats.fail(cand["id"])
                    continue

            if upstream is None:
                writer.write(build_reply(last_rep))
                await writer.drain()
                return

            up_reader, up_writer = upstream
            writer.write(build_reply(REP_OK))
            await writer.drain()
            self.sticky.set(peer, chosen["id"])
            if self.stats:
                self.stats.conn(chosen["id"])

            up, down = await self._pump(reader, writer, up_reader, up_writer)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            pass
        except SocksError:
            pass
        except Exception:
            pass
        finally:
            if self.stats and chosen:
                self.stats.bytes(chosen["id"], up, down)
            try:
                writer.close()
            except Exception:
                pass

    async def _connect(self, exit_cfg, host, port):
        try:
            return await self._connect_inner(exit_cfg, host, port)
        except SocksError:
            raise
        except asyncio.IncompleteReadError:
            raise SocksError(REP_CONN_REFUSED)
        except asyncio.TimeoutError:
            raise SocksError(REP_HOST_UNREACHABLE)
        except (ConnectionError, OSError):
            raise SocksError(REP_CONN_REFUSED)

    async def _connect_inner(self, exit_cfg, host, port):
        kind = exit_cfg["kind"]
        if kind == "direct":
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), self.selector.timeout
            )
            return r, w
        if kind == "socks5" or exit_cfg.get("socks_port"):
            proxy_port = int(exit_cfg.get("socks_port") or 0)
            if not proxy_port:
                ep = exit_cfg.get("endpoint") or ""
                proxy_port = int(ep.rsplit(":", 1)[1]) if ":" in ep else 1080
            return await open_via_socks5(
                exit_cfg.get("endpoint_host") or "127.0.0.1",
                proxy_port,
                host, port, self.selector.timeout,
            )
        raise SocksError(REP_GENERAL_FAILURE)

    async def _pump(self, c_reader, c_writer, u_reader, u_writer):
        up = down = 0

        async def c2u():
            nonlocal up
            try:
                while True:
                    data = await c_reader.read(65536)
                    if not data:
                        break
                    up += len(data)
                    u_writer.write(data)
                    await u_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    u_writer.write_eof()
                except Exception:
                    pass

        async def u2c():
            nonlocal down
            try:
                while True:
                    data = await u_reader.read(65536)
                    if not data:
                        break
                    down += len(data)
                    c_writer.write(data)
                    await c_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    c_writer.write_eof()
                except Exception:
                    pass

        await asyncio.gather(c2u(), u2c(), return_exceptions=True)
        try:
            u_writer.close()
        except Exception:
            pass
        return up, down


class StatsBuffer:
    """Batches per-connection counters into SQLite (avoids a write per byte)."""

    def __init__(self, store, flush_every=5):
        self.store = store
        self.flush_every = flush_every
        self.pending = {}
        self._task = None

    def conn(self, eid):
        self._bump(eid, conns=1)

    def fail(self, eid):
        self._bump(eid, failures=1)

    def bytes(self, eid, up, down):
        if up or down:
            self._bump(eid, up=up, down=down)

    def _bump(self, eid, up=0, down=0, conns=0, failures=0):
        p = self.pending.setdefault(eid, [0, 0, 0, 0])
        p[0] += up
        p[1] += down
        p[2] += conns
        p[3] += failures

    def flush(self):
        if not self.pending:
            return
        pending, self.pending = self.pending, {}
        for eid, (up, down, conns, fails) in pending.items():
            self.store.add_traffic(eid, up, down, conns, fails)

    async def run(self):
        while True:
            await asyncio.sleep(self.flush_every)
            try:
                self.flush()
            except Exception:
                pass
