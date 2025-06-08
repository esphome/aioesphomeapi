from __future__ import annotations

import asyncio

# After we drop support for Python 3.10, we can use the built-in TimeoutError
# instead of the one from asyncio since they are the same in Python 3.11+
from asyncio import CancelledError, TimeoutError as asyncio_TimeoutError
from dataclasses import astuple, dataclass
import enum
from functools import lru_cache, partial
import logging
import socket
import sys
import time
from typing import TYPE_CHECKING, Any, Callable

import aiohappyeyeballs
from async_interrupt import interrupt
from google.protobuf import message
from google.protobuf.json_format import MessageToDict

import aioesphomeapi.host_resolver as hr

from ._frame_helper.noise import APINoiseFrameHelper
from ._frame_helper.plain_text import APIPlaintextFrameHelper
from .api_pb2 import (  # type: ignore
    ConnectRequest,
    ConnectResponse,
    DisconnectRequest,
    DisconnectResponse,
    GetTimeRequest,
    GetTimeResponse,
    HelloRequest,
    HelloResponse,
    PingRequest,
    PingResponse,
)
from .core import (
    MESSAGE_TYPE_TO_PROTO,
    APIConnectionCancelledError,
    APIConnectionError,
    BadNameAPIError,
    ConnectionNotEstablishedAPIError,
    HandshakeAPIError,
    InvalidAuthAPIError,
    PingFailedAPIError,
    ProtocolAPIError,
    ReadFailedAPIError,
    SocketAPIError,
    SocketClosedAPIError,
    TimeoutAPIError,
    UnhandledAPIConnectionError,
)
from .model import APIVersion, message_types_to_names
from .util import asyncio_timeout
from .zeroconf import ZeroconfManager

_LOGGER = logging.getLogger(__name__)

MESSAGE_NUMBER_TO_PROTO: tuple[
    tuple[Callable[[], message.Message], Callable[[message.Message, bytes], None]], ...
] = tuple((msg, msg.MergeFromString) for msg in MESSAGE_TYPE_TO_PROTO.values())


PREFERRED_BUFFER_SIZE = 2097152  # Set buffer limit to 2MB
MIN_BUFFER_SIZE = 131072  # Minimum buffer size to use

DISCONNECT_REQUEST_MESSAGE = DisconnectRequest()
DISCONNECT_RESPONSE_MESSAGES = (DisconnectResponse(),)
PING_REQUEST_MESSAGES = (PingRequest(),)
PING_RESPONSE_MESSAGES = (PingResponse(),)
NO_PASSWORD_CONNECT_REQUEST = ConnectRequest()

PROTO_TO_MESSAGE_TYPE: dict[
    type[message.Message], tuple[int, Callable[[message.Message], bytes]]
] = {v: (k, v.SerializeToString) for k, v in MESSAGE_TYPE_TO_PROTO.items()}

KEEP_ALIVE_TIMEOUT_RATIO = 4.5
#
# We use 4.5x the keep-alive time as the timeout for the pong
# since the default ping interval is 20s which is about the time
# a device takes to reboot and reconnect to the network making
# the maximum time it has to respond to a ping at 90s which is
# enough time to know that the device has truly disconnected
# from the network.
#

DISCONNECT_CONNECT_TIMEOUT = 5.0
# How long to wait for an existing connection to finish being
# setup when requesting a disconnect so we can try to disconnect
# gracefully without closing the socket out from under the
# the esp device

DISCONNECT_RESPONSE_TIMEOUT = 10.0
HANDSHAKE_TIMEOUT = 30.0
CONNECT_REQUEST_TIMEOUT = 30.0

# The connect timeout should be the maximum time we expect the esp to take
# to reboot and connect to the network/WiFi.
TCP_CONNECT_TIMEOUT = 60.0

WRITE_EXCEPTIONS = (RuntimeError, ConnectionResetError, OSError)

_WIN32 = sys.platform == "win32"

_int = int
_bytes = bytes
_float = float


class ConnectionInterruptedError(Exception):
    """An error that is raised when a connection is interrupted."""


@dataclass
class ConnectionParams:
    addresses: list[str]
    port: int
    password: str | None
    client_info: str
    keepalive: float
    zeroconf_manager: ZeroconfManager
    noise_psk: str | None
    expected_name: str | None
    expected_mac: str | None


class ConnectionState(enum.Enum):
    # The connection is initialized, but connect() wasn't called yet
    INITIALIZED = 0
    # The host has been resolved, but the socket hasn't been opened yet
    HOST_RESOLVED = 1
    # The socket has been opened, but the handshake and login haven't been completed
    SOCKET_OPENED = 2
    # The handshake has been completed, messages can be exchanged
    HANDSHAKE_COMPLETE = 3
    # The connection has been established, authenticated data can be exchanged
    CONNECTED = 4
    CLOSED = 5


CONNECTION_STATE_INITIALIZED = ConnectionState.INITIALIZED
CONNECTION_STATE_HOST_RESOLVED = ConnectionState.HOST_RESOLVED
CONNECTION_STATE_SOCKET_OPENED = ConnectionState.SOCKET_OPENED
CONNECTION_STATE_HANDSHAKE_COMPLETE = ConnectionState.HANDSHAKE_COMPLETE
CONNECTION_STATE_CONNECTED = ConnectionState.CONNECTED
CONNECTION_STATE_CLOSED = ConnectionState.CLOSED


def _make_hello_request(client_info: str) -> HelloRequest:
    """Make a HelloRequest."""
    return HelloRequest(
        client_info=client_info, api_version_major=1, api_version_minor=10
    )


_cached_make_hello_request = lru_cache(maxsize=16)(_make_hello_request)
make_hello_request = _cached_make_hello_request


def handle_timeout(fut: asyncio.Future[None]) -> None:
    """Handle a timeout."""
    if not fut.done():
        fut.set_exception(asyncio_TimeoutError)


_handle_timeout = handle_timeout


def handle_complex_message(
    fut: asyncio.Future[None],
    responses: list[message.Message],
    do_append: Callable[[message.Message], bool] | None,
    do_stop: Callable[[message.Message], bool] | None,
    resp: message.Message,
) -> None:
    """Handle a message that is part of a response."""
    if not fut.done():
        if do_append is None or do_append(resp):
            responses.append(resp)
        if do_stop is None or do_stop(resp):
            fut.set_result(None)


_handle_complex_message = handle_complex_message


class APIConnection:
    """This class represents _one_ connection to a remote native API device.

    An instance of this class may only be used once, for every new connection
    a new instance should be established.

    This class should only be created from APIClient and should not be used directly.
    """

    __slots__ = (
        "_addrs_info",
        "_debug_enabled",
        "_expected_disconnect",
        "_fatal_exception",
        "_finish_connect_future",
        "_frame_helper",
        "_handshake_complete",
        "_keep_alive_interval",
        "_keep_alive_timeout",
        "_loop",
        "_message_handlers",
        "_params",
        "_ping_timer",
        "_pong_timer",
        "_read_exception_futures",
        "_resolve_host_future",
        "_send_pending_ping",
        "_socket",
        "_start_connect_future",
        "api_version",
        "connected_address",
        "connection_state",
        "is_connected",
        "log_name",
        "on_stop",
        "received_name",
    )

    def __init__(
        self,
        params: ConnectionParams,
        on_stop: Callable[[bool], None] | None,
        debug_enabled: bool,
        log_name: str | None,
    ) -> None:
        self._params = params
        self.on_stop = on_stop
        self._socket: socket.socket | None = None
        self._frame_helper: None | APINoiseFrameHelper | APIPlaintextFrameHelper = None
        self.api_version: APIVersion | None = None

        self.connection_state = CONNECTION_STATE_INITIALIZED

        # Message handlers currently subscribed to incoming messages
        self._message_handlers: dict[Any, set[Callable[[message.Message], None]]] = {}
        # The friendly name to show for this connection in the logs
        self.log_name = log_name or ",".join(params.addresses)

        # futures currently subscribed to exceptions in the read task
        self._read_exception_futures: set[asyncio.Future[None]] = set()

        self._ping_timer: asyncio.TimerHandle | None = None
        self._pong_timer: asyncio.TimerHandle | None = None
        keepalive = params.keepalive
        self._keep_alive_interval = keepalive
        self._keep_alive_timeout = keepalive * KEEP_ALIVE_TIMEOUT_RATIO

        self._resolve_host_future: asyncio.Future[None] | None = None
        self._start_connect_future: asyncio.Future[None] | None = None
        self._finish_connect_future: asyncio.Future[None] | None = None
        self._fatal_exception: Exception | None = None
        self._expected_disconnect = False
        self._send_pending_ping = False
        self._loop = asyncio.get_running_loop()
        self.is_connected = False
        self._handshake_complete = False
        self._debug_enabled = debug_enabled
        self.received_name: str = ""
        self.connected_address: str | None = None
        self._addrs_info: list[hr.AddrInfo] = []

    def set_log_name(self, name: str) -> None:
        """Set the friendly log name for this connection."""
        self.log_name = name
        if self._frame_helper is not None:
            self._frame_helper.set_log_name(name)

    def _cleanup(self) -> None:
        """Clean up all resources that have been allocated.

        Safe to call multiple times.
        """
        if self.connection_state is CONNECTION_STATE_CLOSED:
            return
        was_connected = self.is_connected
        self._set_connection_state(CONNECTION_STATE_CLOSED)
        if self._debug_enabled:
            _LOGGER.debug("Cleaning up connection to %s", self.log_name)
        for fut in self._read_exception_futures:
            if not fut.done():
                err = self._fatal_exception or APIConnectionError("Connection closed")
                new_exc = err
                if not isinstance(err, APIConnectionError):
                    new_exc = ReadFailedAPIError(str(err) or "Read failed")
                    new_exc.__cause__ = err
                fut.set_exception(new_exc)
        self._read_exception_futures.clear()

        self._set_resolve_host_future()
        self._set_start_connect_future()
        self._set_finish_connect_future()

        if self._frame_helper is not None:
            self._frame_helper.close()
            self._frame_helper = None

        if self._socket is not None:
            self._socket.close()
            self._socket = None

        self._async_cancel_pong_timer()

        if self._ping_timer is not None:
            self._ping_timer.cancel()
            self._ping_timer = None

        if (on_stop := self.on_stop) is not None and was_connected:
            self.on_stop = None
            on_stop(self._expected_disconnect)

    def set_debug(self, enable: bool) -> None:
        """Enable or disable debug logging."""
        self._debug_enabled = enable

    async def _connect_socket_connect(self, addrs: list[hr.AddrInfo]) -> None:
        """Step 2 in connect process: connect the socket."""
        if self._debug_enabled:
            _LOGGER.debug(
                "%s: Connecting to %s",
                self.log_name,
                ", ".join(str(addr.sockaddr) for addr in addrs),
            )

        addr_infos: list[aiohappyeyeballs.AddrInfoType] = [
            (
                addr.family,
                addr.type,
                addr.proto,
                "",
                astuple(addr.sockaddr),
            )
            for addr in addrs
        ]
        last_exception: Exception | None = None
        sock: socket.socket | None = None
        interleave = 1
        while addr_infos:
            try:
                async with asyncio_timeout(TCP_CONNECT_TIMEOUT):
                    # Devices are likely on the local network so we
                    # only use a 100ms happy eyeballs delay
                    sock = await aiohappyeyeballs.start_connection(
                        addr_infos,
                        happy_eyeballs_delay=0.1,
                        interleave=interleave,
                        loop=self._loop,
                    )
                    break
            except (OSError, asyncio_TimeoutError) as err:
                last_exception = err
                aiohappyeyeballs.pop_addr_infos_interleave(addr_infos, interleave)

        if sock is None:
            if isinstance(last_exception, asyncio_TimeoutError):
                raise TimeoutAPIError(
                    f"Timeout while connecting to {addrs}"
                ) from last_exception
            raise SocketAPIError(
                f"Error connecting to {addrs}: {last_exception}"
            ) from last_exception

        self._socket = sock
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)  # type: ignore[attr-defined, unused-ignore]
        except (AttributeError, OSError):  # On FreeBSD this may throw OSError
            _LOGGER.debug(
                "%s: TCP_QUICKACK not supported",
                self.log_name,
            )
        self._increase_recv_buffer_size()
        self.connected_address = sock.getpeername()[0]

        if self._debug_enabled:
            _LOGGER.debug(
                "%s: Opened socket to %s:%s",
                self.log_name,
                self.connected_address,
                self._params.port,
            )

    def _increase_recv_buffer_size(self) -> None:
        """Increase the recv buffer size."""
        if TYPE_CHECKING:
            assert self._socket is not None
        new_buffer_size = PREFERRED_BUFFER_SIZE
        while True:
            # Try to reduce the pressure on ESPHome device as it measures
            # ram in bytes and we measure ram in megabytes.
            try:
                self._socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, new_buffer_size
                )
            except OSError as err:  # noqa: PERF203
                if new_buffer_size <= MIN_BUFFER_SIZE:
                    _LOGGER.warning(
                        "%s: Unable to increase the socket receive buffer size to %s; "
                        "The connection may unstable if the ESPHome device sends "
                        "data at volume (ex. a Bluetooth proxy or camera): %s",
                        self.log_name,
                        new_buffer_size,
                        err,
                    )
                    return
                new_buffer_size //= 2
            else:
                return

    async def _connect_init_frame_helper(self) -> None:
        """Step 3 in connect process: initialize the frame helper and init read loop."""
        fh: APIPlaintextFrameHelper | APINoiseFrameHelper
        if TYPE_CHECKING:
            assert self._socket is not None

        if (noise_psk := self._params.noise_psk) is None:
            _, fh = await self._loop.create_connection(  # type: ignore[type-var]
                lambda: APIPlaintextFrameHelper(
                    connection=self,
                    client_info=self._params.client_info,
                    log_name=self.log_name,
                ),
                sock=self._socket,
            )
        else:
            _, fh = await self._loop.create_connection(  # type: ignore[type-var]
                lambda: APINoiseFrameHelper(
                    noise_psk=noise_psk,
                    expected_name=self._params.expected_name,
                    expected_mac=self._params.expected_mac,
                    connection=self,
                    client_info=self._params.client_info,
                    log_name=self.log_name,
                ),
                sock=self._socket,
            )

        # Set the frame helper right away to ensure
        # the socket gets closed if we fail to handshake
        self._frame_helper = fh
        handshake_handle = self._loop.call_at(
            self._loop.time() + HANDSHAKE_TIMEOUT,
            _handle_timeout,
            self._frame_helper.ready_future,
        )
        try:
            await self._frame_helper.ready_future
        except asyncio_TimeoutError as err:
            raise TimeoutAPIError(
                f"Handshake timed out after {HANDSHAKE_TIMEOUT}s"
            ) from err
        except OSError as err:
            raise HandshakeAPIError(f"Handshake failed: {err}") from err
        finally:
            handshake_handle.cancel()
        self._set_connection_state(CONNECTION_STATE_HANDSHAKE_COMPLETE)

    async def _connect_hello_login(self, login: bool) -> None:
        """Step 4 in connect process: send hello and login and get api version."""
        messages = [make_hello_request(self._params.client_info)]
        msg_types = [HelloResponse]
        if login:
            messages.append(self._make_connect_request())
            msg_types.append(ConnectResponse)

        responses = await self.send_messages_await_response_complex(
            tuple(messages),
            None,
            lambda resp: type(resp)  # pylint: disable=unidiomatic-typecheck
            is msg_types[-1],
            tuple(msg_types),
            CONNECT_REQUEST_TIMEOUT,
        )
        resp = responses.pop(0)
        self._process_hello_resp(resp)
        if login:
            login_response = responses.pop(0)
            self._process_login_response(login_response)

    def _process_login_response(self, login_response: ConnectResponse) -> None:
        """Process a ConnectResponse."""
        if login_response.invalid_password:
            raise InvalidAuthAPIError("Invalid password!")

    def _process_hello_resp(self, resp: HelloResponse) -> None:
        """Process a HelloResponse."""
        if self._debug_enabled:
            _LOGGER.debug(
                "%s: Successfully connected ('%s' API=%s.%s)",
                self.log_name,
                resp.server_info,
                resp.api_version_major,
                resp.api_version_minor,
            )
        api_version = APIVersion(resp.api_version_major, resp.api_version_minor)
        if api_version.major > 2:
            _LOGGER.error(
                "%s: Incompatible version %s! Closing connection",
                self.log_name,
                api_version.major,
            )
            raise APIConnectionError(f"Incompatible API version ({api_version}).")

        self.api_version = api_version
        expected_name = self._params.expected_name
        if received_name := resp.name:
            if expected_name is not None and received_name != expected_name:
                raise BadNameAPIError(
                    f"Expected '{expected_name}' but server sent "
                    f"a different name: '{received_name}'",
                    received_name,
                )

            self.received_name = received_name
            self.set_log_name(self.received_name)

    def _async_schedule_keep_alive(self, now: _float) -> None:
        """Start the keep alive task."""
        self._send_pending_ping = True
        self._ping_timer = self._loop.call_at(
            now + self._keep_alive_interval, self._async_send_keep_alive
        )

    def _async_send_keep_alive(self) -> None:
        """Send a keep alive message."""
        now = self._loop.time()

        if self._send_pending_ping:
            self.send_messages(PING_REQUEST_MESSAGES)
            if self._pong_timer is None:
                # Do not reset the timer if it's already set
                # since the only thing we want to reset the timer
                # is if we receive a pong.
                self._pong_timer = self._loop.call_at(
                    now + self._keep_alive_timeout, self._async_pong_not_received
                )
            elif self._debug_enabled:
                #
                # We haven't reached the ping response (pong) timeout yet
                # and we haven't seen a response to the last ping
                #
                # We send another ping in case the device has
                # rebooted and dropped the connection without telling
                # us to force a TCP RST aka connection reset by peer.
                #
                _LOGGER.debug(
                    "%s: PingResponse (pong) was not received "
                    "since last keep alive after %s seconds; "
                    "rescheduling keep alive",
                    self.log_name,
                    self._keep_alive_interval,
                )

        self._async_schedule_keep_alive(now)

    def _async_cancel_pong_timer(self) -> None:
        """Cancel the pong timer."""
        if self._pong_timer is not None:
            self._pong_timer.cancel()
            self._pong_timer = None

    def _async_pong_not_received(self) -> None:
        """Ping not received."""
        if self._debug_enabled:
            _LOGGER.debug(
                "%s: Ping response not received after %s seconds",
                self.log_name,
                self._keep_alive_timeout,
            )
        self.report_fatal_error(
            PingFailedAPIError(
                f"Ping response not received after {self._keep_alive_timeout} seconds"
            )
        )

    async def start_resolve_host(self) -> None:
        """Start the host resolution process.

        This part of the process resolves the hostnames to IP addresses
        and prepares the connection for the next step.
        """
        if self.connection_state is not CONNECTION_STATE_INITIALIZED:
            raise RuntimeError(
                "Connection can only be used once, connection is not in init state"
            )

        self._resolve_host_future = self._loop.create_future()
        try:
            async with interrupt(
                self._resolve_host_future, ConnectionInterruptedError, None
            ):
                self._addrs_info = await hr.async_resolve_host(
                    self._params.addresses,
                    self._params.port,
                    self._params.zeroconf_manager,
                )
        except (Exception, CancelledError) as ex:
            # If the task was cancelled, we need to clean up the connection
            # and raise the CancelledError as APIConnectionError
            self._cleanup()
            raise self._wrap_fatal_connection_exception("resolving", ex)
        finally:
            self._set_resolve_host_future()
        self._set_connection_state(CONNECTION_STATE_HOST_RESOLVED)

    def _set_resolve_host_future(self) -> None:
        if (
            self._resolve_host_future is not None
            and not self._resolve_host_future.done()
        ):
            self._resolve_host_future.set_result(None)
            self._resolve_host_future = None

    async def start_connection(self) -> None:
        """Start the connection process.

        This part of the process establishes the socket connection but
        does not initialize the frame helper or send the hello message.
        """
        if self.connection_state is not CONNECTION_STATE_HOST_RESOLVED:
            raise RuntimeError(
                "Connection must be in HOST_RESOLVED state to start connection"
            )

        self._start_connect_future = self._loop.create_future()
        try:
            async with interrupt(
                self._start_connect_future, ConnectionInterruptedError, None
            ):
                await self._connect_socket_connect(self._addrs_info)
        except (Exception, CancelledError) as ex:
            # If the task was cancelled, we need to clean up the connection
            # and raise the CancelledError as APIConnectionError
            self._cleanup()
            raise self._wrap_fatal_connection_exception("starting", ex)
        finally:
            self._set_start_connect_future()
        self._set_connection_state(CONNECTION_STATE_SOCKET_OPENED)

    def _set_start_connect_future(self) -> None:
        if (
            self._start_connect_future is not None
            and not self._start_connect_future.done()
        ):
            self._start_connect_future.set_result(None)
            self._start_connect_future = None

    def _wrap_fatal_connection_exception(
        self, action: str, ex: BaseException
    ) -> APIConnectionError:
        """Ensure a fatal exception is wrapped as as an APIConnectionError."""
        if isinstance(ex, APIConnectionError):
            return ex
        cause: BaseException | None = None
        if isinstance(ex, (ConnectionInterruptedError, CancelledError)):
            err_str = f"{action.title()} connection cancelled"
            if self._fatal_exception:
                err_str += f" due to fatal exception: {self._fatal_exception}"
                cause = self._fatal_exception
        else:
            err_str = str(ex) or type(ex).__name__
            cause = ex
        if isinstance(self._fatal_exception, APIConnectionError):
            klass = type(self._fatal_exception)
        elif isinstance(ex, CancelledError):
            klass = APIConnectionCancelledError
        elif isinstance(ex, OSError):
            klass = SocketAPIError
        else:
            klass = UnhandledAPIConnectionError
        new_exc = klass(f"Error while {action} connection: {err_str}")
        new_exc.__cause__ = cause or ex
        return new_exc

    async def _do_finish_connect(self, login: bool) -> None:
        """Finish the connection process."""
        # Register internal handlers before
        # connecting the helper so we can ensure
        # we handle any messages that are received immediately
        self._register_internal_message_handlers()
        await self._connect_init_frame_helper()
        await self._connect_hello_login(login)
        self._async_schedule_keep_alive(self._loop.time())

    async def finish_connection(self, *, login: bool) -> None:
        """Finish the connection process.

        This part of the process initializes the frame helper and sends the hello message
        than starts the keep alive process.
        """
        if self.connection_state is not CONNECTION_STATE_SOCKET_OPENED:
            raise RuntimeError(
                "Connection must be in SOCKET_OPENED state to finish connection"
            )
        self._finish_connect_future = self._loop.create_future()
        try:
            async with interrupt(
                self._finish_connect_future, ConnectionInterruptedError, None
            ):
                await self._do_finish_connect(login)
        except (Exception, CancelledError) as ex:
            # If the task was cancelled, we need to clean up the connection
            # and raise the CancelledError as APIConnectionError
            self._cleanup()
            raise self._wrap_fatal_connection_exception("finishing", ex)
        finally:
            self._set_finish_connect_future()
        self._set_connection_state(CONNECTION_STATE_CONNECTED)

    def _set_finish_connect_future(self) -> None:
        if (
            self._finish_connect_future is not None
            and not self._finish_connect_future.done()
        ):
            self._finish_connect_future.set_result(None)
            self._finish_connect_future = None

    def _set_connection_state(self, state: ConnectionState) -> None:
        """Set the connection state and log the change."""
        self.connection_state = state
        self.is_connected = state is CONNECTION_STATE_CONNECTED
        self._handshake_complete = (
            state is CONNECTION_STATE_HANDSHAKE_COMPLETE
            or state is CONNECTION_STATE_CONNECTED
        )

    def _make_connect_request(self) -> ConnectRequest:
        """Make a ConnectRequest."""
        if self._params.password is not None:
            return ConnectRequest(password=self._params.password)
        return NO_PASSWORD_CONNECT_REQUEST

    def send_message(self, msg: message.Message) -> None:
        """Send a message to the remote."""
        self.send_messages((msg,))

    def send_messages(self, msgs: tuple[message.Message, ...]) -> None:
        """Send a protobuf message to the remote."""
        if not self._handshake_complete:
            raise ConnectionNotEstablishedAPIError(
                f"Connection isn't established yet ({self.connection_state})"
            )

        packets: list[tuple[int, bytes]] = [
            (msg_type[0], msg_type[1](msg))
            for msg in msgs
            if (msg_type := PROTO_TO_MESSAGE_TYPE[type(msg)])
        ]
        if self._debug_enabled:
            for msg in msgs:
                _LOGGER.debug(
                    "%s: Sending %s: %s",
                    self.log_name,
                    type(msg).__name__,
                    # calling __str__ on the message may crash on
                    # Windows systems due to a bug in the protobuf library
                    # so we call MessageToDict instead
                    MessageToDict(msg) if _WIN32 else msg,
                )

        if TYPE_CHECKING:
            assert self._frame_helper is not None

        try:
            self._frame_helper.write_packets(packets, self._debug_enabled)
        except WRITE_EXCEPTIONS as err:
            # If writing packet fails, we don't know what state the frames
            # are in anymore and we have to close the connection
            _LOGGER.info("%s: Error writing packets: %s", self.log_name, err)
            wrapped_err = SocketClosedAPIError(
                f"{self.log_name}: Error writing packets: {err}"
            )
            wrapped_err.__cause__ = err
            self.report_fatal_error(wrapped_err)
            raise wrapped_err from err

    def _add_message_callback_without_remove(
        self, on_message: Callable[[Any], None], msg_types: tuple[type[Any], ...]
    ) -> None:
        """Add a message callback without returning a remove callable."""
        for msg_type in msg_types:
            if (handlers := self._message_handlers.get(msg_type)) is None:
                self._message_handlers[msg_type] = {on_message}
            else:
                handlers.add(on_message)

    def add_message_callback(
        self, on_message: Callable[[Any], None], msg_types: tuple[type[Any], ...]
    ) -> Callable[[], None]:
        """Add a message callback."""
        self._add_message_callback_without_remove(on_message, msg_types)
        return partial(self._remove_message_callback, on_message, msg_types)

    def _remove_message_callback(
        self, on_message: Callable[[Any], None], msg_types: tuple[type[Any], ...]
    ) -> None:
        """Remove a message callback."""
        for msg_type in msg_types:
            handlers = self._message_handlers[msg_type]
            handlers.discard(on_message)

    def send_message_callback_response(
        self,
        send_msg: message.Message,
        on_message: Callable[[Any], None],
        msg_types: tuple[type[Any], ...],
    ) -> Callable[[], None]:
        """Send a message to the remote and register the given message handler."""
        self.send_messages((send_msg,))
        # Since we do not return control to the event loop (no awaits)
        # between sending the message and registering the handler
        # we can be sure that we will not miss any messages even though
        # we register the handler after sending the message
        return self.add_message_callback(on_message, msg_types)

    async def send_messages_await_response_complex(  # pylint: disable=too-many-locals
        self,
        messages: tuple[message.Message, ...],
        do_append: Callable[[message.Message], bool] | None,
        do_stop: Callable[[message.Message], bool] | None,
        msg_types: tuple[type[Any], ...],
        timeout: _float,
    ) -> list[message.Message]:
        """Send a message to the remote and build up a list response.

        :param send_msg: The message (request) to send.
        :param do_append: Predicate to check if a received message is part of the response.
        :param do_stop: Predicate to check if a received message is the stop response.
        :param timeout: The maximum amount of time to wait for the stop response.

        :raises TimeoutAPIError: if a timeout occurred
        """
        # Send the message right away to reduce latency.
        # This is safe because we are not awaiting between
        # sending the message and registering the handler
        self.send_messages(messages)
        # Unsafe to await between sending the message and registering the handler
        fut: asyncio.Future[None] = self._loop.create_future()
        responses: list[message.Message] = []
        on_message = partial(
            _handle_complex_message, fut, responses, do_append, do_stop
        )
        self._add_message_callback_without_remove(on_message, msg_types)

        self._read_exception_futures.add(fut)
        # Now safe to await since we have registered the handler

        # We must not await without a finally or
        # the message could fail to be removed if the
        # the await is cancelled
        timeout_handle = self._loop.call_at(
            self._loop.time() + timeout, _handle_timeout, fut
        )
        timeout_expired = False
        try:
            await fut
        except asyncio_TimeoutError as err:
            timeout_expired = True
            response_names = message_types_to_names(msg_types)
            raise TimeoutAPIError(
                f"Timeout waiting for {response_names} after {timeout}s"
            ) from err
        finally:
            if not timeout_expired:
                timeout_handle.cancel()
            self._remove_message_callback(on_message, msg_types)
            self._read_exception_futures.discard(fut)

        return responses

    async def send_message_await_response(
        self, send_msg: message.Message, response_type: Any, timeout: _float = 10.0
    ) -> Any:
        [response] = await self.send_messages_await_response_complex(
            (send_msg,),
            None,  # we will only get responses of `response_type`
            None,  # we will only get responses of `response_type`
            (response_type,),
            timeout,
        )
        return response

    def report_fatal_error(self, err: Exception) -> None:
        """Report a fatal error that occurred during an operation.

        This should only be called for errors that mean the connection
        can no longer be used.

        The connection will be closed, all exception handlers notified.
        This method does not log the error, the call site should do so.
        """
        if self._fatal_exception is None:
            if self._expected_disconnect is False:
                # Only log the first error
                _LOGGER.warning(
                    "%s: Connection error occurred: %s",
                    self.log_name,
                    err or type(err),
                    exc_info=not str(err),  # Log the full stack on empty error string
                )

            # Only set the first error since otherwise the original
            # error will be lost (ie RequiresEncryptionAPIError) and than
            # SocketClosedAPIError will be raised instead
            self._set_fatal_exception_if_unset(err)

        self._cleanup()

    def _set_fatal_exception_if_unset(self, err: Exception) -> None:
        """Set the fatal exception if it hasn't been set yet."""
        if self._fatal_exception is None:
            self._fatal_exception = err

    def process_packet(self, msg_type_proto: _int, data: _bytes) -> None:
        """Process an incoming packet."""
        # This method is HOT and extremely performance critical
        # since its called for every incoming packet. Take
        # extra care when modifying this method.
        try:
            # MESSAGE_NUMBER_TO_PROTO is 0-indexed
            # but the message type is 1-indexed
            klass_merge = MESSAGE_NUMBER_TO_PROTO[msg_type_proto - 1]
            klass, merge = klass_merge
            msg = klass()
            merge(msg, data)
        except Exception as e:
            # IndexError will be very rare so we check for it
            # after the broad exception catch to avoid having
            # to check the exception type twice for the common case
            if isinstance(e, IndexError):
                if self._debug_enabled:
                    _LOGGER.debug(
                        "%s: Skipping unknown message type %s",
                        self.log_name,
                        msg_type_proto,
                    )
                return
            _LOGGER.exception(
                "%s: Invalid protobuf message: type=%s data=%s",
                self.log_name,
                klass.__name__,
                data,
            )
            self.report_fatal_error(
                ProtocolAPIError(
                    f"Invalid protobuf message: type={klass.__name__} data={data!r}: {e}"
                )
            )
            raise

        if self._debug_enabled:
            _LOGGER.debug(
                "%s: Got message of type %s: %s",
                self.log_name,
                type(msg).__name__,
                # calling __str__ on the message may crash on
                # Windows systems due to a bug in the protobuf library
                # so we call MessageToDict instead
                MessageToDict(msg) if _WIN32 else msg,
            )

        if self._pong_timer is not None:
            # Any valid message from the remote cancels the pong timer
            # as we know the connection is still alive
            self._async_cancel_pong_timer()

        if self._send_pending_ping:
            # Any valid message from the remove cancels the pending ping
            # since we know the connection is still alive
            self._send_pending_ping = False

        if (handlers := self._message_handlers.get(type(msg))) is None:
            return

        if len(handlers) > 1:
            # Handlers are allowed to remove themselves
            # so we need to copy the set to avoid a
            # runtime error if the set is modified during
            # iteration. This can only if there is more
            # than one handler registered for the message
            # type.
            handlers_copy = handlers.copy()
            for handler in handlers_copy:
                handler(msg)
            return

        # Most common case, only one handler:
        # no need to copy the set. We still
        # use a loop here even though there is
        # only one handler because Cython will
        # poorly optimize next(iter(handlers))
        for handler in handlers:
            handler(msg)
            break

    def _register_internal_message_handlers(self) -> None:
        """Register internal message handlers."""
        self._add_message_callback_without_remove(
            self._handle_disconnect_request_internal, (DisconnectRequest,)
        )
        self._add_message_callback_without_remove(
            self._handle_ping_request_internal, (PingRequest,)
        )
        self._add_message_callback_without_remove(
            self._handle_get_time_request_internal, (GetTimeRequest,)
        )

    def _handle_disconnect_request_internal(  # pylint: disable=unused-argument
        self, _msg: DisconnectRequest
    ) -> None:
        """Handle a DisconnectRequest."""
        # Set _expected_disconnect to True before sending
        # the response if for some reason sending the response
        # fails we will still mark the disconnect as expected
        self._expected_disconnect = True
        self.send_messages(DISCONNECT_RESPONSE_MESSAGES)
        self._cleanup()

    def _handle_ping_request_internal(  # pylint: disable=unused-argument
        self, _msg: PingRequest
    ) -> None:
        """Handle a PingRequest."""
        self.send_messages(PING_RESPONSE_MESSAGES)

    def _handle_get_time_request_internal(  # pylint: disable=unused-argument
        self, _msg: GetTimeRequest
    ) -> None:
        """Handle a GetTimeRequest."""
        resp = GetTimeResponse()
        resp.epoch_seconds = int(time.time())
        self.send_messages((resp,))

    async def disconnect(self) -> None:
        """Disconnect from the API."""
        if self._finish_connect_future is not None:
            # Try to wait for the handshake to finish so we can send
            # a disconnect request. If it doesn't finish in time
            # we will just close the socket.
            _, pending = await asyncio.wait(
                [self._finish_connect_future], timeout=DISCONNECT_CONNECT_TIMEOUT
            )
            if pending:
                self._set_fatal_exception_if_unset(
                    TimeoutAPIError(
                        "Timed out waiting to finish connect before disconnecting"
                    )
                )
                if self._debug_enabled:
                    _LOGGER.debug(
                        "%s: Connect task didn't finish before disconnect",
                        self.log_name,
                    )

        self._expected_disconnect = True
        if self._handshake_complete:
            # We still want to send a disconnect request even
            # if the hello phase isn't finished to ensure we
            # the esp will clean up the connection as soon
            # as possible.
            try:
                await self.send_message_await_response(
                    DISCONNECT_REQUEST_MESSAGE,
                    DisconnectResponse,
                    timeout=DISCONNECT_RESPONSE_TIMEOUT,
                )
            except APIConnectionError:
                _LOGGER.exception("%s: disconnect request failed", self.log_name)

        self._cleanup()

    def force_disconnect(self) -> None:
        """Forcefully disconnect from the API."""
        self._expected_disconnect = True
        if self._handshake_complete:
            # Still try to tell the esp to disconnect gracefully
            # but don't wait for it to finish
            try:
                self.send_messages((DISCONNECT_REQUEST_MESSAGE,))
            except APIConnectionError:
                _LOGGER.exception(
                    "%s: Failed to send (forced) disconnect request",
                    self.log_name,
                )

        self._cleanup()
