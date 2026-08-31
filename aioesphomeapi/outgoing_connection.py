"""Listener for device-initiated (outgoing) API connections.

An ESPHome device with the ``api: outgoing_connection:`` option opens the TCP
connection to us when no dial-back client is connected to it. The protocol
roles do not change: the device stays the server and Noise responder, so once
the socket is adopted the normal client machinery runs unchanged.

To let us pick the right encryption key before the PSK-mixed handshake
starts, the device sends its server hello (name and MAC) first on these
connections. This module peeks at those bytes without consuming them, looks
up the registered :class:`ReconnectLogic` for the MAC, and hands the socket
over via :meth:`ReconnectLogic.async_adopt_connection`; the frame helper then
reads the server hello from the socket as usual.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from typing import TYPE_CHECKING

from .util import asyncio_timeout, create_eager_task

if TYPE_CHECKING:
    from collections.abc import Callable

    from .reconnect_logic import ReconnectLogic

_LOGGER = logging.getLogger(__name__)

DEFAULT_OUTGOING_CONNECTION_PORT = 6054
# How long an accepted connection may take to identify itself
IDENTIFY_TIMEOUT = 10.0
# Cap on concurrent connections that have not identified themselves yet
MAX_PENDING = 8
# The hello frame is tiny (name + MAC); anything larger is not a hello
MAX_HELLO_SIZE = 128
_ACCEPT_ERROR_BACKOFF = 1.0
# Delay between peeks while a hello frame is still incomplete
_PEEK_RETRY_DELAY = 0.05


def _normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").lower()


def _parse_server_hello(data: bytes) -> tuple[str, str] | None:
    """Parse the device's unsolicited server hello.

    Returns (name, mac) when complete, None when more bytes are needed, and
    raises ValueError when the bytes cannot be a server hello.
    """
    if len(data) < 3:
        return None
    if data[0] != 0x01:
        msg = f"not a noise frame (indicator {data[0]})"
        raise ValueError(msg)
    frame_len = (data[1] << 8) | data[2]
    if frame_len < 2 or frame_len > MAX_HELLO_SIZE - 3:
        msg = f"bad hello frame length {frame_len}"
        raise ValueError(msg)
    if len(data) < 3 + frame_len:
        return None
    payload = data[3 : 3 + frame_len]
    if payload[0] != 0x01:
        msg = f"unsupported protocol byte {payload[0]}"
        raise ValueError(msg)
    parts = payload[1:].split(b"\x00")
    if len(parts) < 2:
        msg = "malformed hello payload"
        raise ValueError(msg)
    name = parts[0].decode("utf-8", "replace")
    mac = parts[1].decode("ascii", "replace").lower()
    if len(mac) != 12:
        msg = f"malformed MAC {mac!r}"
        raise ValueError(msg)
    return name, mac


class OutgoingConnectionServer:
    """Accepts connections that ESPHome devices open to this host.

    Consumers register a MAC address with the :class:`ReconnectLogic` that
    should take over when that device dials in; everything wire-level is
    handled here.
    """

    def __init__(
        self,
        port: int = DEFAULT_OUTGOING_CONNECTION_PORT,
        host: str | None = None,
    ) -> None:
        self._port = port
        self._host = host
        self._targets: dict[str, ReconnectLogic] = {}
        self._server_socket: socket.socket | None = None
        self._accept_task: asyncio.Task[None] | None = None
        self._pending: set[asyncio.Task[None]] = set()

    @property
    def port(self) -> int:
        """The listening port; resolved after start() when created with port 0."""
        return self._port

    def register(self, mac: str, reconnect_logic: ReconnectLogic) -> Callable[[], None]:
        """Route dial-ins from the device with this MAC to a ReconnectLogic.

        The MAC may contain ``:`` or ``-`` separators and any case. Returns a
        callable that removes the registration.
        """
        mac = _normalize_mac(mac)
        if mac in self._targets:
            msg = f"MAC {mac} is already registered"
            raise ValueError(msg)
        self._targets[mac] = reconnect_logic

        def _unregister() -> None:
            self._targets.pop(mac, None)

        return _unregister

    async def start(self) -> None:
        """Open the listening socket and start accepting connections.

        Raises OSError when the port cannot be bound.
        """
        if self._server_socket is not None:
            return
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            with contextlib.suppress(AttributeError, OSError):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind((self._host or "::", self._port))
        except OSError:
            # Fall back to IPv4 only (no IPv6 stack, or a v4 literal host)
            if sock is not None:
                sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((self._host or "", self._port))
            except OSError:
                sock.close()
                raise
        sock.listen(4)
        sock.setblocking(False)
        self._server_socket = sock
        self._port = sock.getsockname()[1]
        self._accept_task = create_eager_task(
            self._accept_loop(sock), name=f"esphome-outgoing-connection-{self._port}"
        )
        _LOGGER.debug("Listening for outgoing connections on port %s", self._port)

    async def stop(self) -> None:
        """Stop accepting and close the listening socket.

        Established sessions that were already handed to a ReconnectLogic
        keep running.
        """
        if self._accept_task is not None:
            self._accept_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._accept_task
            self._accept_task = None
        for task in list(self._pending):
            task.cancel()
        self._pending.clear()
        if self._server_socket is not None:
            self._server_socket.close()
            self._server_socket = None

    async def _accept_loop(self, sock: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                conn, addr = await loop.sock_accept(sock)
            except OSError:
                if self._server_socket is None:
                    return
                await asyncio.sleep(_ACCEPT_ERROR_BACKOFF)
                continue
            if len(self._pending) >= MAX_PENDING:
                _LOGGER.warning("Too many unidentified connections; rejecting %s", addr)
                conn.close()
                continue
            conn.setblocking(False)
            task = create_eager_task(
                self._identify_and_dispatch(conn, addr),
                name=f"esphome-outgoing-connection-identify-{addr}",
            )
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)

    async def _identify_and_dispatch(
        self, conn: socket.socket, addr: tuple[object, ...]
    ) -> None:
        try:
            async with asyncio_timeout(IDENTIFY_TIMEOUT):
                name, mac = await self._peek_server_hello(conn)
        except (TimeoutError, OSError, ValueError, asyncio.CancelledError) as err:
            _LOGGER.debug("Rejecting connection from %s: %s", addr, err)
            conn.close()
            if isinstance(err, asyncio.CancelledError):
                raise
            return
        if (target := self._targets.get(mac)) is None:
            _LOGGER.debug(
                "No registered target for %s (%s) dialing in from %s", mac, name, addr
            )
            conn.close()
            return
        _LOGGER.debug("Device %s (%s) dialed in from %s", name, mac, addr)
        # async_adopt_connection takes ownership of the socket either way
        await target.async_adopt_connection(conn)

    async def _peek_server_hello(self, conn: socket.socket) -> tuple[str, str]:
        """Read the server hello with MSG_PEEK, leaving the bytes in the socket."""
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = conn.recv(MAX_HELLO_SIZE, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                await _wait_readable(loop, conn)
                continue
            if not data:
                msg = "connection closed before hello"
                raise ValueError(msg)
            if (result := _parse_server_hello(data)) is not None:
                return result
            # Frame incomplete; the fd stays readable with the peeked bytes,
            # so wait a moment instead of spinning on the reader callback
            await asyncio.sleep(_PEEK_RETRY_DELAY)


async def _wait_readable(loop: asyncio.AbstractEventLoop, conn: socket.socket) -> None:
    fut: asyncio.Future[None] = loop.create_future()
    fd = conn.fileno()
    loop.add_reader(fd, fut.set_result, None)
    try:
        await fut
    finally:
        loop.remove_reader(fd)
