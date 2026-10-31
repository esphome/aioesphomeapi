"""A fake ESPHome device: a plaintext API server plus its mDNS announcements."""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import TYPE_CHECKING

from zeroconf import DNSOutgoing, ServiceInfo
from zeroconf.const import _FLAGS_AA, _FLAGS_QR_RESPONSE

from aioesphomeapi.api_pb2 import (  # type: ignore[attr-defined]
    DisconnectRequest,
    DisconnectResponse,
    HelloRequest,
    HelloResponse,
    PingRequest,
    PingResponse,
)
from aioesphomeapi.core import MESSAGE_TYPE_TO_PROTO

from ..common import generate_plaintext_packet

if TYPE_CHECKING:
    from google.protobuf import message
    from zeroconf import DNSRecord
    from zeroconf.asyncio import AsyncZeroconf

LOOPBACK = "127.0.0.1"
SERVICE = "_esphomelib._tcp.local."
# Loopback delivery plus zeroconf's handling of a packet.
DELIVERY_WAIT = 0.5


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
            self._handle(MESSAGE_TYPE_TO_PROTO.get(msg_type))

    def _send(self, msg: message.Message) -> None:
        assert self.transport is not None
        self.transport.write(generate_plaintext_packet(msg))

    def _handle(self, msg_cls: type[message.Message] | None) -> None:
        assert self.transport is not None
        if msg_cls is HelloRequest:
            self._send(
                HelloResponse(
                    api_version_major=1,
                    api_version_minor=12,
                    server_info="fake",
                    name=self._device.name,
                )
            )
        elif msg_cls is PingRequest:
            self._send(PingResponse())
        elif msg_cls is DisconnectRequest:
            self._send(DisconnectResponse())
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
        """Stop listening and drop every connection; a no-op when stopped."""
        if self._server is None:
            return
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

    def _records(self, kind: str) -> list[DNSRecord]:
        info = ServiceInfo(
            SERVICE,
            f"{self.name}.{SERVICE}",
            port=self.port,
            properties={"version": "dev"},
            server=f"{self.name}.local.",
            addresses=[socket.inet_aton(LOOPBACK)],
        )
        records: list[DNSRecord] = []
        if kind in ("all", "service"):
            records += [info.dns_pointer(), info.dns_service(), info.dns_text()]
        if kind in ("all", "host"):
            records += info.dns_addresses()
        return records
