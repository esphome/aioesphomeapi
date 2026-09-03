"""Listener for device-initiated (outgoing) API connections.

A device with ``api: outgoing_connection:`` dials this host when no
dial-back client is connected, sending its server hello (name and MAC)
first so the right encryption key can be chosen. The hello is peeked
without consuming it and the socket is adopted by the
:class:`ReconnectLogic` registered for the MAC.
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
# Distinct rejection keys reported at INFO per window before dropping to DEBUG
_MAX_INFO_KEYS_LOGGED = 32
_INFO_LOG_WINDOW = 3600.0
# The hello frame is tiny (name + MAC); anything larger is not a hello
_MAX_HELLO_SIZE = 128
_ACCEPT_ERROR_BACKOFF = 1.0
# A recurring bind failure re-warns after this long instead of staying at info
_BIND_WARN_INTERVAL = 3600.0
# Broken-listener errnos; everything else accept(2) raises is transient
_FATAL_ACCEPT_ERRNOS = frozenset({errno.EBADF, errno.ENOTSOCK, errno.EINVAL})
# Delay between peeks while the hello frame is still incomplete
_PEEK_RETRY_DELAY = 0.05


def _normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").lower()


def _is_valid_mac(mac: str) -> bool:
    return len(mac) == 12 and all(c in "0123456789abcdef" for c in mac)


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
    # Peer-supplied; sanitize before it can reach a log line
    name = safe_label_str(name_bytes.decode("utf-8", "replace"), MAX_NAME_LEN)
    mac = mac_bytes.decode("ascii", "replace").lower()
    # Devices announce a bare 12-hex-digit MAC; this also keeps peer
    # bytes from forging log lines
    if not _is_valid_mac(mac):
        msg = f"malformed MAC {mac!r}"
        raise ValueError(msg)
    return name, mac


class OutgoingConnectionServer:
    """Accepts connections that ESPHome devices open to this host.

    ``register()`` maps a MAC to the :class:`ReconnectLogic` that adopts
    its dial-ins and drives the listener lifecycle: the first registration
    opens it, removing the last one closes it and frees the port, and a
    bind failure or fatal accept error is retried on the next registration.

    The MAC in the hello is unauthenticated: adoption never preempts an
    established session, the Noise handshake rejects a peer without the
    claimed MAC's key, and a hostile dial-in costs at most one ordinary
    backoff step, so the worst case is wasted handshakes.
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
        # Insertion-ordered for oldest-eviction; the socket value lets
        # eviction close a task that never ran
        self._pending: dict[asyncio.Task[None], socket.socket] = {}
        # Rejection keys already reported at INFO; bounded against scans
        self._info_keys_logged: set[str] = set()
        self._info_keys_cleared = 0.0
        # One adoption in flight per MAC; extras would queue on the
        # ReconnectLogic lock holding an fd each. Values are strong task refs
        self._adopting: dict[str, asyncio.Task[None]] = {}
        # None until a bind fails; holds the last warning time after
        self._last_bind_warning: float | None = None

    @property
    def port(self) -> int:
        """The listening port; resolved after start() when created with port 0."""
        return self._port

    @property
    def is_listening(self) -> bool:
        """False before start(), after close(), or when the listener died."""
        return self._server_socket is not None

    def register(self, mac: str, reconnect_logic: ReconnectLogic) -> Callable[[], None]:
        """Route dial-ins from the device with this MAC to a ReconnectLogic.

        Separators and case in the MAC are normalized. Returns a callable
        that removes the registration; it never raises. A bind failure is
        logged, not raised: the route stays registered and the bind is
        retried on the next registration.
        """
        mac = _normalize_mac(mac)
        # A MAC the hello parser can never produce would silently never
        # adopt; fail at the wiring site instead
        if not _is_valid_mac(mac):
            msg = f"invalid MAC {mac!r}; expected 12 hex digits"
            raise ValueError(msg)
        if mac in self._targets:
            msg = f"MAC {mac} is already registered"
            raise ValueError(msg)
        self._targets[mac] = reconnect_logic
        self._ensure_listening()

        def _unregister() -> None:
            # Identity-guarded against stale callables
            if self._targets.get(mac) is reconnect_logic:
                del self._targets[mac]
                if not self._targets:
                    self.close()

        return _unregister

    def _ensure_listening(self) -> None:
        """Open the listener if needed; warn once per window on bind failure."""
        if self.is_listening:
            return
        try:
            self.start()
        except OSError as err:
            now = asyncio.get_running_loop().time()
            last = self._last_bind_warning
            level = logging.INFO
            if last is None or now - last >= _BIND_WARN_INTERVAL:
                self._last_bind_warning = now
                level = logging.WARNING
            _LOGGER.log(
                level,
                "Cannot listen for outgoing connections on port %s: %s;"
                " will retry on the next registration",
                self._port,
                err,
            )
            return
        if self._last_bind_warning is not None:
            self._last_bind_warning = None
            _LOGGER.info(
                "Listening for outgoing connections on port %s after an"
                " earlier failure",
                self._port,
            )

    def start(self) -> None:
        """Open the listening socket; raises OSError when the port is taken.

        Synchronous; the accept loop runs as a background task.
        """
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
        self._accept_task.add_done_callback(self._accept_task_done)
        _LOGGER.debug("Listening for outgoing connections on port %s", self._port)

    def close(self) -> None:
        """Stop accepting and close the listening socket; never raises.

        Synchronous: the port is free when this returns. Sessions already
        handed to a ReconnectLogic keep running.
        """
        # Close directly; a task that never ran has no handler to close its socket
        for task, conn in self._pending.items():
            task.cancel()
            conn.close()
        self._pending.clear()
        self._release_socket()
        if (accept_task := self._accept_task) is not None:
            self._accept_task = None
            accept_task.cancel()

    def _release_socket(self) -> None:
        if self._server_socket is not None:
            self._server_socket.close()
            self._server_socket = None

    @staticmethod
    def _log_task_exception(task: asyncio.Task[None]) -> None:
        if not task.cancelled() and (exc := task.exception()) is not None:
            _LOGGER.error("Unexpected error in %s", task.get_name(), exc_info=exc)

    def _accept_task_done(self, task: asyncio.Task[None]) -> None:
        self._log_task_exception(task)
        if task.cancelled() or task.exception() is None:
            return  # normal close(); it owns the cleanup
        if self._accept_task is not task:
            return  # a restart already replaced this listener
        # The listener is dead; release the socket so start() can rebind
        self._accept_task = None
        self._release_socket()

    def _identify_done(self, task: asyncio.Task[None]) -> None:
        self._log_task_exception(task)
        self._pending.pop(task, None)

    def _log_rate_limited(self, key: str, msg: str, *args: object) -> None:
        """Log INFO once per key and window so a misconfiguration surfaces."""
        now = asyncio.get_running_loop().time()
        if now - self._info_keys_cleared >= _INFO_LOG_WINDOW:
            self._info_keys_logged.clear()
            self._info_keys_cleared = now
        level = logging.DEBUG
        if (
            key not in self._info_keys_logged
            and len(self._info_keys_logged) < _MAX_INFO_KEYS_LOGGED
        ):
            self._info_keys_logged.add(key)
            level = logging.INFO
        _LOGGER.log(level, msg, *args)

    async def _accept_loop(self, sock: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                conn, addr = await loop.sock_accept(sock)
            except OSError as err:
                if err.errno in _FATAL_ACCEPT_ERRNOS:
                    raise  # broken listener; die loudly via the done callback
                _LOGGER.warning("Error accepting outgoing connection: %s", err)
                await asyncio.sleep(_ACCEPT_ERROR_BACKOFF)
                continue
            if len(self._pending) >= _MAX_PENDING:
                # Evict the oldest unidentified connection; a real device
                # identifies within milliseconds
                oldest, oldest_conn = next(iter(self._pending.items()))
                self._log_rate_limited(
                    f"evict:{addr[0]}",
                    "Too many unidentified connections; evicting oldest for %s",
                    addr,
                )
                self._pending.pop(oldest, None)
                oldest.cancel()
                oldest_conn.close()  # the task body may never have started
            conn.setblocking(False)
            # Not eager: the task must be in _pending before it first runs
            task = loop.create_task(
                self._identify_and_dispatch(conn, addr),
                name=f"esphome-outgoing-connection-identify-{addr}",
            )
            task.add_done_callback(self._identify_done)
            self._pending[task] = conn

    async def _identify_and_dispatch(
        self, conn: socket.socket, addr: tuple[object, ...]
    ) -> None:
        # The stack owns the socket until adoption takes it over
        with contextlib.ExitStack() as stack:
            stack.callback(conn.close)
            try:
                async with asyncio_timeout(_IDENTIFY_TIMEOUT):
                    name, mac = await self._peek_server_hello(conn)
            except (TimeoutError, OSError, ValueError) as err:
                # Rate limited, not silent: a plaintext or skewed device
                # must stay diagnosable
                self._log_rate_limited(
                    f"reject:{addr[0]}", "Rejecting connection from %s: %s", addr, err
                )
                return
            if (target := self._targets.get(mac)) is None:
                self._log_rate_limited(
                    f"mac:{mac}",
                    "No registered target for %s (%s) dialing in from %s",
                    mac,
                    name,
                    addr,
                )
                return
            if mac in self._adopting:
                _LOGGER.debug(
                    "Adoption already in flight for %s; closing %s", mac, addr
                )
                return
            _LOGGER.debug("Device %s (%s) dialed in from %s", name, mac, addr)
            # Leave the pending set so a slow handshake holds no admission slot
            if (current := asyncio.current_task()) is not None:
                self._pending.pop(current, None)
                self._adopting[mac] = current
            try:
                # async_adopt_connection takes ownership of the socket on all
                # its paths; the stack still closes it if this raises
                adopted = await target.async_adopt_connection(conn)
            finally:
                self._adopting.pop(mac, None)
            stack.pop_all()
        if not adopted:
            _LOGGER.info("Dial-in from %s (%s) was not adopted", name, addr)

    async def _peek_server_hello(self, conn: socket.socket) -> tuple[str, str]:
        """Read the server hello with MSG_PEEK, leaving the bytes in the socket."""
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = conn.recv(_MAX_HELLO_SIZE, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                # Nothing buffered yet; wait for readability
                fut: asyncio.Future[None] = loop.create_future()
                fd = conn.fileno()
                try:
                    loop.add_reader(fd, fut.set_result, None)
                except NotImplementedError:
                    # Proactor loop (Windows) cannot watch readability
                    await asyncio.sleep(_PEEK_RETRY_DELAY)
                    continue
                try:
                    await fut
                finally:
                    loop.remove_reader(fd)
                continue
            if not data:
                msg = "connection closed before hello"
                raise ValueError(msg)
            if (result := _parse_server_hello(data)) is not None:
                return result
            # Peeked bytes keep the fd readable, so a reader would spin
            await asyncio.sleep(_PEEK_RETRY_DELAY)
