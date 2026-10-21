"""A minimal SOCKS5 server used as a test fixture (direct egress)."""

import asyncio
import socket
import struct


async def _pipe(r, w):
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def _handle(reader, writer, counter):
    try:
        ver, n = await reader.readexactly(2)
        await reader.readexactly(n)
        writer.write(b"\x05\x00")
        await writer.drain()

        ver, cmd, _rsv, atyp = await reader.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode()
        else:
            host = str(await reader.readexactly(16))
        port = struct.unpack("!H", await reader.readexactly(2))[0]

        ur, uw = await asyncio.open_connection(host, port)
        counter["n"] += 1
        writer.write(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + struct.pack("!H", 0))
        await writer.drain()
        await asyncio.gather(_pipe(reader, uw), _pipe(ur, writer), return_exceptions=True)
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class FixtureSocks:
    def __init__(self, port=0):
        self.port = port
        self.counter = {"n": 0}
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(
            lambda r, w: _handle(r, w, self.counter), "127.0.0.1", self.port)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
