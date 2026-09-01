"""Listener for device-initiated (outgoing) API connections.

A device with the ``api: outgoing_connection:`` option opens the TCP
connection to us when no dial-back client is connected to it, sending its
server hello (name and MAC) first so the right encryption key can be chosen
before the PSK-mixed handshake starts. Protocol roles are unchanged. The
hello is peeked without consuming it, the :class:`ReconnectLogic` registered
for the MAC gets the socket via ``async_adopt_connection``, and the frame
helper then reads the hello from the socket as usual.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import logging
import socket
from typing import TYPE_CHECKING

from ._sanitize import MAX_NAME_LEN, safe_label_str
from .util import asyncio_timeout, create_eager_task

if TYPE_CHECKING:
    from collections.abc import Callable

    from .reconnect_logic import ReconnectLogic

_LOGGER = logging.getLogger(__name__)

DEFAULT_OUTGOING_CONNECTION_PORT = 6054
# How long an accepted connection may take to identify itself
_IDENTIFY_TIMEOUT = 10.0
# Cap on concurrent connections that have not identified themselves yet
_MAX_PENDING = 8
# The hello frame is tiny (name + MAC); anything larger is not a hello
_MAX_HELLO_SIZE = 128
_ACCEPT_ERROR_BACKOFF = 1.0
# Accept failures that clear up on their own; anything else (EBADF, EINVAL,
# ...) means the listening socket is broken and retrying cannot help
_RETRYABLE_ACCEPT_ERRNOS = frozenset(
    {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ECONNABORTED}
)
# Delay between peeks while the hello frame is still incomplete
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
    if frame_len < 2 or frame_len > _MAX_HELLO_SIZE - 3:
        msg = f"bad hello frame length {frame_len}"
        raise ValueError(msg)
    if len(data) < 3 + frame_len:
        return None
    payload = data[3 : 3 + frame_len]
    if payload[0] != 0x01:
        msg = f"unsupported protocol byte {payload[0]}"
        raise ValueError(msg)
    name_bytes, name_sep, rest = payload[1:].partition(b"\x00")
    mac_bytes, mac_sep, _ = rest.partition(b"\x00")
    if not name_sep or not mac_sep:
        msg = "malformed hello payload"
        raise ValueError(msg)
    # The name is peer-supplied; sanitize before it can reach a log line
    name = safe_label_str(name_bytes.decode("utf-8", "replace"), MAX_NAME_LEN)
    mac = mac_bytes.decode("ascii", "replace").lower()
    # Devices that dial out always announce their bare 12-hex-digit MAC
    if len(mac) != 12:
        msg = f"malformed MAC {mac!r}"
        raise ValueError(msg)
    return name, mac


class OutgoingConnectionServer:
    """Accepts connections that ESPHome devices open to this host.

    Consumers register a MAC address with the :class:`ReconnectLogic` that
    should take over when that device dials in; everything wire-level is
    handled here.

    The MAC in the hello is unauthenticated pre-handshake data: anything on
    the network can dial in claiming a registered MAC. Adoption refuses to
    preempt an established session, the Noise handshake rejects an impostor,
    and a failed adoption cannot escalate the reconnect backoff by more than
    one ordinary attempt per dial-in (repeated hostile dial-ins can still
    walk it to the normal ceiling), so the worst case is wasted handshakes
    and ordinary backoff. Only Noise devices can dial out, so a plaintext
    hello never matches and is rejected during identification.
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
        # Adoptions in progress: kept only as strong references so the tasks
        # cannot be garbage collected; stop() leaves them running
        self._adopting: set[asyncio.Task[None]] = set()

    @property
    def port(self) -> int:
        """The listening port; resolved after start() when created with port 0."""
        return self._port

    def register(self, mac: str, reconnect_logic: ReconnectLogic) -> Callable[[], None]:
        """Route dial-ins from the device with this MAC to a ReconnectLogic.

        The MAC may contain ``:`` or ``-`` separators and any case. Returns
        a callable that removes the registration; call it when the
        ReconnectLogic is discarded, the registry holds a strong reference.
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
        """Open the listening socket; raises OSError when the port is taken."""
        if self._server_socket is not None:
            return
        if self._host is None and socket.has_dualstack_ipv6():
            sock = socket.create_server(
                ("::", self._port),
                family=socket.AF_INET6,
                dualstack_ipv6=True,
                backlog=4,
            )
        else:
            sock = socket.create_server((self._host or "", self._port), backlog=4)
        sock.setblocking(False)
        self._server_socket = sock
        self._port = sock.getsockname()[1]
        self._accept_task = create_eager_task(
            self._accept_loop(sock), name=f"esphome-outgoing-connection-{self._port}"
        )
        # Surface an unexpected death of the accept loop instead of silence
        self._accept_task.add_done_callback(self._log_task_exception)
        _LOGGER.debug("Listening for outgoing connections on port %s", self._port)

    async def stop(self) -> None:
        """Stop accepting and close the listening socket.

        Sessions already handed to a ReconnectLogic keep running.
        """
        if self._accept_task is not None:
            self._accept_task.cancel()
            # A crash was already logged; it must not skip the cleanup below
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._accept_task
            self._accept_task = None
        if pending := tuple(self._pending):
            for task in pending:
                task.cancel()
            # Wait so each task's CancelledError handler closes its socket
            await asyncio.gather(*pending, return_exceptions=True)
        if self._server_socket is not None:
            self._server_socket.close()
            self._server_socket = None

    @staticmethod
    def _log_task_exception(task: asyncio.Task[None]) -> None:
        if not task.cancelled() and (exc := task.exception()) is not None:
            _LOGGER.error("Unexpected error in %s", task.get_name(), exc_info=exc)

    async def _accept_loop(self, sock: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                conn, addr = await loop.sock_accept(sock)
            except OSError as err:
                if err.errno not in _RETRYABLE_ACCEPT_ERRNOS:
                    raise  # broken listener; die loudly via the done callback
                _LOGGER.warning("Error accepting outgoing connection: %s", err)
                await asyncio.sleep(_ACCEPT_ERROR_BACKOFF)
                continue
            if len(self._pending) >= _MAX_PENDING:
                _LOGGER.warning("Too many unidentified connections; rejecting %s", addr)
                conn.close()
                continue
            conn.setblocking(False)
            # Deliberately not eager: the task must not run before it is in
            # _pending, or the identification bookkeeping races
            task = loop.create_task(
                self._identify_and_dispatch(conn, addr),
                name=f"esphome-outgoing-connection-identify-{addr}",
            )
            task.add_done_callback(self._log_task_exception)
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)

    async def _identify_and_dispatch(
        self, conn: socket.socket, addr: tuple[object, ...]
    ) -> None:
        try:
            async with asyncio_timeout(_IDENTIFY_TIMEOUT):
                name, mac = await self._peek_server_hello(conn)
        except asyncio.CancelledError:
            conn.close()
            raise
        except (TimeoutError, OSError, ValueError) as err:
            _LOGGER.debug("Rejecting connection from %s: %s", addr, err)
            conn.close()
            return
        if (target := self._targets.get(mac)) is None:
            _LOGGER.debug(
                "No registered target for %s (%s) dialing in from %s", mac, name, addr
            )
            conn.close()
            return
        _LOGGER.debug("Device %s (%s) dialed in from %s", name, mac, addr)
        # Identification is done: leave the pending set so a slow handshake
        # does not hold an admission slot, and so stop() leaves it running.
        # _adopting keeps a strong reference so the task is not collected.
        if (current := asyncio.current_task()) is not None:
            self._pending.discard(current)
            self._adopting.add(current)
            current.add_done_callback(self._adopting.discard)
        # async_adopt_connection takes ownership of the socket either way
        if not await target.async_adopt_connection(conn):
            _LOGGER.debug("Dial-in from %s (%s) was not adopted", name, addr)

    async def _peek_server_hello(self, conn: socket.socket) -> tuple[str, str]:
        """Read the server hello with MSG_PEEK, leaving the bytes in the socket."""
        while True:
            try:
                data = conn.recv(_MAX_HELLO_SIZE, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                pass  # nothing buffered yet
            else:
                if not data:
                    msg = "connection closed before hello"
                    raise ValueError(msg)
                if (result := _parse_server_hello(data)) is not None:
                    return result
            # The peeked bytes keep the fd readable, so a reader callback
            # would spin; a short sleep is enough for a frame this small
            await asyncio.sleep(_PEEK_RETRY_DELAY)
