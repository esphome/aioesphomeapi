"""A fake ESPHome device: a plaintext API server plus its mDNS announcements."""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import TYPE_CHECKING

from zeroconf import DNSAddress, DNSOutgoing, DNSPointer, DNSService, DNSText
from zeroconf.const import (
    _CLASS_IN,
    _CLASS_UNIQUE,
    _FLAGS_AA,
    _FLAGS_QR_RESPONSE,
    _TYPE_A,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
)

from aioesphomeapi._frame_helper.packets import make_plain_text_packets
from aioesphomeapi.api_pb2 import DisconnectResponse, HelloResponse, PingResponse  # type: ignore[attr-defined]

if TYPE_CHECKING:
    from zeroconf.asyncio import AsyncZeroconf

LOOPBACK = "127.0.0.1"
SERVICE = "_esphomelib._tcp.local."
# Loopback delivery plus zeroconf's handling of a packet.
DELIVERY_WAIT = 0.5

HELLO_REQUEST = 1
HELLO_RESPONSE = 2
DISCONNECT_REQUEST = 5
DISCONNECT_RESPONSE = 6
PING_REQUEST = 7
PING_RESPONSE = 8


def _read_varuint(buf: bytes, pos: int) -> tuple[int, int]:
    """Decode a varuint at pos; -1 when the buffer ends first."""
    result = shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
    return -1, pos


class _DeviceProtocol(asyncio.Protocol):
    """Answer hello, ping and disconnect; reset the connection once stale."""

    def __init__(self, device: FakeDevice) -> None:
        self._device = device
        self._buf = b""
        self.transport: asyncio.Transport | None = None
        self.stale = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self._device.connections.append(self)

    def connection_lost(self, exc: Exception | None) -> None:
        if self in self._device.connections:
            self._device.connections.remove(self)

    def data_received(self, data: bytes) -> None:
        assert self.transport is not None
        if self.stale:
            # A rebooted device has no state for this connection, so the
            # first packet the client sends is answered with a TCP RST.
            sock = self.transport.get_extra_info("socket")
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
            self.transport.abort()
            return
        self._buf += data
        while self._buf and self._buf[0] == 0:
            length, pos = _read_varuint(self._buf, 1)
            if length < 0:
                return
            msg_type, pos = _read_varuint(self._buf, pos)
            if msg_type < 0 or len(self._buf) < pos + length:
                return
            self._buf = self._buf[pos + length :]
            self._handle(msg_type)

    def _send(self, msg_type: int, msg: object) -> None:
        assert self.transport is not None
        payload = msg.SerializeToString()  # type: ignore[attr-defined]
        self.transport.writelines(make_plain_text_packets([(msg_type, payload)]))

    def _handle(self, msg_type: int) -> None:
        if msg_type == HELLO_REQUEST:
            hello = HelloResponse(api_version_major=1, api_version_minor=12)
            hello.server_info = "fake"
            hello.name = self._device.name
            self._send(HELLO_RESPONSE, hello)
        elif msg_type == PING_REQUEST:
            self._send(PING_RESPONSE, PingResponse())
        elif msg_type == DISCONNECT_REQUEST:
            assert self.transport is not None
            self._send(DISCONNECT_RESPONSE, DisconnectResponse())
            self.transport.close()


class FakeDevice:
    """A device named name serving the API on loopback and announcing over mDNS."""

    def __init__(self, name: str, responder: AsyncZeroconf) -> None:
        self.name = name
        self.connections: list[_DeviceProtocol] = []
        self.port = 0
        self._responder = responder
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Listen for API connections, on the same port after a restart."""
        loop = asyncio.get_running_loop()
        self._server = await loop.create_server(
            lambda: _DeviceProtocol(self), LOOPBACK, self.port, reuse_address=True
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        """Stop listening and drop every connection."""
        assert self._server is not None
        self._server.close()
        for conn in list(self.connections):
            assert conn.transport is not None
            conn.transport.abort()
        await self._server.wait_closed()
        self._server = None

    def reboot(self) -> None:
        """Forget every open connection silently, as a power cycle does."""
        for conn in self.connections:
            conn.stale = True

    def send_packet(self, kind: str = "all") -> None:
        """Multicast one response packet with host, service or all records."""
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        for record in self._records(kind):
            out.add_answer_at_time(record, 0)
        self._responder.zeroconf.async_send(out)

    async def announce(self, rounds: list[tuple[float, tuple[str, ...]]]) -> None:
        """Send rounds of packets, then wait for them to be received and handled.

        Each round is (ms to wait before it, packet kinds).
        """
        for delay_ms, kinds in rounds:
            await asyncio.sleep(delay_ms / 1000)
            for index, kind in enumerate(kinds):
                if index:
                    await asyncio.sleep(0.005)
                self.send_packet(kind)
        await asyncio.sleep(DELIVERY_WAIT)

    def _records(self, kind: str) -> list[object]:
        instance = f"{self.name}.{SERVICE}"
        host = f"{self.name}.local."
        unique = _CLASS_IN | _CLASS_UNIQUE
        records: list[object] = []
        if kind in ("all", "service"):
            records += [
                DNSPointer(SERVICE, _TYPE_PTR, _CLASS_IN, 4500, instance),
                DNSService(instance, _TYPE_SRV, unique, 120, 0, 0, self.port, host),
                DNSText(instance, _TYPE_TXT, unique, 4500, b"\x0bversion=dev"),
            ]
        if kind in ("all", "host"):
            records.append(
                DNSAddress(host, _TYPE_A, unique, 120, socket.inet_aton(LOOPBACK))
            )
        return records
