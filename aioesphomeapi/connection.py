from __future__ import annotations

import asyncio
import enum
import logging
import socket
import sys
import time

# After we drop support for Python 3.10, we can use the built-in TimeoutError
# instead of the one from asyncio since they are the same in Python 3.11+
from asyncio import CancelledError
from asyncio import TimeoutError as asyncio_TimeoutError
from dataclasses import astuple, dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Callable

from google.protobuf import message

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
    ResolveAPIError,
    SocketAPIError,
    TimeoutAPIError,
    UnhandledAPIConnectionError,
)
from .model import APIVersion
from .zeroconf import ZeroconfManager

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout
else:
    from asyncio import timeout as asyncio_timeout


_LOGGER = logging.getLogger(__name__)

BUFFER_SIZE = 1024 * 1024 * 2  # Set buffer limit to 2MB

DISCONNECT_REQUEST_MESSAGE = DisconnectRequest()
DISCONNECT_RESPONSE_MESSAGE = DisconnectResponse()
PING_REQUEST_MESSAGE = PingRequest()
PING_RESPONSE_MESSAGE = PingResponse()

PROTO_TO_MESSAGE_TYPE = {v: k for k, v in MESSAGE_TYPE_TO_PROTO.items()}

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
RESOLVE_TIMEOUT = 30.0
CONNECT_REQUEST_TIMEOUT = 30.0

# The connect timeout should be the maximum time we expect the esp to take
# to reboot and connect to the network/WiFi.
TCP_CONNECT_TIMEOUT = 60.0


_int = int
_bytes = bytes
_float = float


@dataclass
class ConnectionParams:
    address: str
    port: int
    password: str | None
    client_info: str
    keepalive: float
    zeroconf_manager: ZeroconfManager
    noise_psk: str | None
    expected_name: str | None


class ConnectionState(enum.Enum):
    # The connection is initialized, but connect() wasn't called yet
    INITIALIZED = 0
    # The socket has been opened, but the handshake and login haven't been completed
    SOCKET_OPENED = 1
    # The handshake has been completed, messages can be exchanged
    HANDSHAKE_COMPLETE = 2
    # The connection has been established, authenticated data can be exchanged
    CONNECTED = 2
    CLOSED = 3


CONNECTION_STATE_INITIALIZED = ConnectionState.INITIALIZED
CONNECTION_STATE_SOCKET_OPENED = ConnectionState.SOCKET_OPENED
CONNECTION_STATE_HANDSHAKE_COMPLETE = ConnectionState.HANDSHAKE_COMPLETE
CONNECTION_STATE_CONNECTED = ConnectionState.CONNECTED
CONNECTION_STATE_CLOSED = ConnectionState.CLOSED


class APIConnection:
    """This class represents _one_ connection to a remote native API device.

    An instance of this class may only be used once, for every new connection
    a new instance should be established.

    This class should only be created from APIClient and should not be used directly.
    """

    __slots__ = (
        "_params",
        "on_stop",
        "_socket",
        "_frame_helper",
        "api_version",
        "connection_state",
        "_message_handlers",
        "log_name",
        "_read_exception_futures",
        "_ping_timer",
        "_pong_timer",
        "_keep_alive_interval",
        "_keep_alive_timeout",
        "_start_connect_task",
        "_finish_connect_task",
        "_fatal_exception",
        "_expected_disconnect",
        "_loop",
        "_send_pending_ping",
        "is_connected",
        "_handshake_complete",
        "_debug_enabled",
        "received_name",
        "resolved_addr_info",
    )

    def __init__(
        self,
        params: ConnectionParams,
        on_stop: Callable[[bool], None],
        debug_enabled: bool,
        log_name: str | None,
    ) -> None:
        self._params = params
        self.on_stop: Callable[[bool], None] | None = on_stop
        self._socket: socket.socket | None = None
        self._frame_helper: None | (
            APINoiseFrameHelper | APIPlaintextFrameHelper
        ) = None
        self.api_version: APIVersion | None = None

        self.connection_state = CONNECTION_STATE_INITIALIZED

        # Message handlers currently subscribed to incoming messages
        self._message_handlers: dict[Any, set[Callable[[message.Message], None]]] = {}
        # The friendly name to show for this connection in the logs
        self.log_name = log_name or params.address

        # futures currently subscribed to exceptions in the read task
        self._read_exception_futures: set[asyncio.Future[None]] = set()

        self._ping_timer: asyncio.TimerHandle | None = None
        self._pong_timer: asyncio.TimerHandle | None = None
        keepalive = params.keepalive
        self._keep_alive_interval = keepalive
        self._keep_alive_timeout = keepalive * KEEP_ALIVE_TIMEOUT_RATIO

        self._start_connect_task: asyncio.Task[None] | None = None
        self._finish_connect_task: asyncio.Task[None] | None = None
        self._fatal_exception: Exception | None = None
        self._expected_disconnect = False
        self._send_pending_ping = False
        self._loop = asyncio.get_event_loop()
        self.is_connected = False
        self._handshake_complete = False
        self._debug_enabled = debug_enabled
        self.received_name: str = ""
        self.resolved_addr_info: hr.AddrInfo | None = None

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
                    new_exc = ReadFailedAPIError("Read failed")
                    new_exc.__cause__ = err
                fut.set_exception(new_exc)
        self._read_exception_futures.clear()
        # If we are being called from do_connect we
        # need to make sure we don't cancel the task
        # that called us
        current_task = asyncio.current_task()

        if (
            self._start_connect_task is not None
            and self._start_connect_task is not current_task
        ):
            self._start_connect_task.cancel("Connection cleanup")
            self._start_connect_task = None

        if (
            self._finish_connect_task is not None
            and self._finish_connect_task is not current_task
        ):
            self._finish_connect_task.cancel("Connection cleanup")
            self._finish_connect_task = None

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

    async def _connect_resolve_host(self) -> hr.AddrInfo:
        """Step 1 in connect process: resolve the address."""
        try:
            async with asyncio_timeout(RESOLVE_TIMEOUT):
                return await hr.async_resolve_host(
                    self._params.address,
                    self._params.port,
                    self._params.zeroconf_manager,
                )
        except asyncio_TimeoutError as err:
            raise ResolveAPIError(
                f"Timeout while resolving IP address for {self.log_name}"
            ) from err

    async def _connect_socket_connect(self, addr: hr.AddrInfo) -> None:
        """Step 2 in connect process: connect the socket."""
        sock = socket.socket(family=addr.family, type=addr.type, proto=addr.proto)
        self._socket = sock
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Try to reduce the pressure on esphome device as it measures
        # ram in bytes and we measure ram in megabytes.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE)

        if self._debug_enabled:
            _LOGGER.debug(
                "%s: Connecting to %s:%s (%s)",
                self.log_name,
                self._params.address,
                self._params.port,
                addr,
            )
        sockaddr = astuple(addr.sockaddr)

        try:
            async with asyncio_timeout(TCP_CONNECT_TIMEOUT):
                await self._loop.sock_connect(sock, sockaddr)
        except asyncio_TimeoutError as err:
            raise SocketAPIError(f"Timeout while connecting to {sockaddr}") from err
        except OSError as err:
            raise SocketAPIError(f"Error connecting to {sockaddr}: {err}") from err

        if self._debug_enabled:
            _LOGGER.debug(
                "%s: Opened socket to %s:%s (%s)",
                self.log_name,
                self._params.address,
                self._params.port,
                addr,
            )

    async def _connect_init_frame_helper(self) -> None:
        """Step 3 in connect process: initialize the frame helper and init read loop."""
        fh: APIPlaintextFrameHelper | APINoiseFrameHelper
        loop = self._loop
        if TYPE_CHECKING:
            assert self._socket is not None

        if (noise_psk := self._params.noise_psk) is None:
            _, fh = await loop.create_connection(  # type: ignore[type-var]
                lambda: APIPlaintextFrameHelper(
                    connection=self,
                    client_info=self._params.client_info,
                    log_name=self.log_name,
                ),
                sock=self._socket,
            )
        else:
            _, fh = await loop.create_connection(  # type: ignore[type-var]
                lambda: APINoiseFrameHelper(
                    noise_psk=noise_psk,
                    expected_name=self._params.expected_name,
                    connection=self,
                    client_info=self._params.client_info,
                    log_name=self.log_name,
                ),
                sock=self._socket,
            )

        # Set the frame helper right away to ensure
        # the socket gets closed if we fail to handshake
        self._frame_helper = fh

        try:
            await fh.perform_handshake(HANDSHAKE_TIMEOUT)
        except asyncio_TimeoutError as err:
            raise TimeoutAPIError("Handshake timed out") from err
        except OSError as err:
            raise HandshakeAPIError(f"Handshake failed: {err}") from err
        self._set_connection_state(CONNECTION_STATE_HANDSHAKE_COMPLETE)

    async def _connect_hello_login(self, login: bool) -> None:
        """Step 4 in connect process: send hello and login and get api version."""
        messages = [
            HelloRequest(
                client_info=self._params.client_info,
                api_version_major=1,
                api_version_minor=9,
            )
        ]
        msg_types = [HelloResponse]
        if login:
            messages.append(self._make_connect_request())
            msg_types.append(ConnectResponse)

        try:
            responses = await self.send_messages_await_response_complex(
                tuple(messages),
                None,
                lambda resp: type(resp)  # pylint: disable=unidiomatic-typecheck
                is msg_types[-1],
                tuple(msg_types),
                CONNECT_REQUEST_TIMEOUT,
            )
        except TimeoutAPIError as err:
            self.report_fatal_error(err)
            raise TimeoutAPIError("Hello timed out") from err

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
        loop = self._loop
        now = loop.time()

        if self._send_pending_ping:
            self.send_messages((PING_REQUEST_MESSAGE,))
            if self._pong_timer is None:
                # Do not reset the timer if it's already set
                # since the only thing we want to reset the timer
                # is if we receive a pong.
                self._pong_timer = loop.call_at(
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

    async def _do_connect(self) -> None:
        """Do the actual connect process."""
        self.resolved_addr_info = await self._connect_resolve_host()
        await self._connect_socket_connect(self.resolved_addr_info)

    async def start_connection(self) -> None:
        """Start the connection process.

        This part of the process establishes the socket connection but
        does not initialize the frame helper or send the hello message.
        """
        if self.connection_state is not CONNECTION_STATE_INITIALIZED:
            raise RuntimeError(
                "Connection can only be used once, connection is not in init state"
            )

        start_connect_task = asyncio.create_task(
            self._do_connect(), name=f"{self.log_name}: aioesphomeapi do_connect"
        )
        self._start_connect_task = start_connect_task
        try:
            await start_connect_task
        except (Exception, CancelledError) as ex:
            # If the task was cancelled, we need to clean up the connection
            # and raise the CancelledError as APIConnectionError
            self._cleanup()
            raise self._wrap_fatal_connection_exception("starting", ex)
        finally:
            self._start_connect_task = None
        self._set_connection_state(CONNECTION_STATE_SOCKET_OPENED)

    def _wrap_fatal_connection_exception(
        self, action: str, ex: BaseException
    ) -> APIConnectionError:
        """Ensure a fatal exception is wrapped as as an APIConnectionError."""
        if isinstance(ex, APIConnectionError):
            return ex
        cause: BaseException | None = None
        if isinstance(ex, CancelledError):
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
        await self._connect_init_frame_helper()
        self._register_internal_message_handlers()
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
        finish_connect_task = asyncio.create_task(
            self._do_finish_connect(login),
            name=f"{self.log_name}: aioesphomeapi _do_finish_connect",
        )
        self._finish_connect_task = finish_connect_task
        try:
            await self._finish_connect_task
        except (Exception, CancelledError) as ex:
            # If the task was cancelled, we need to clean up the connection
            # and raise the CancelledError as APIConnectionError
            self._cleanup()
            raise self._wrap_fatal_connection_exception("finishing", ex)
        finally:
            self._finish_connect_task = None
        self._set_connection_state(CONNECTION_STATE_CONNECTED)

    def _set_connection_state(self, state: ConnectionState) -> None:
        """Set the connection state and log the change."""
        self.connection_state = state
        self.is_connected = state is CONNECTION_STATE_CONNECTED
        self._handshake_complete = state is CONNECTION_STATE_HANDSHAKE_COMPLETE

    def _make_connect_request(self) -> ConnectRequest:
        """Make a ConnectRequest."""
        connect = ConnectRequest()
        if self._params.password is not None:
            connect.password = self._params.password
        return connect

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
            (PROTO_TO_MESSAGE_TYPE[type(msg)], msg.SerializeToString()) for msg in msgs
        ]

        if debug_enabled := self._debug_enabled:
            for msg in msgs:
                _LOGGER.debug(
                    "%s: Sending %s: %s", self.log_name, type(msg).__name__, msg
                )

        if TYPE_CHECKING:
            assert self._frame_helper is not None

        try:
            self._frame_helper.write_packets(packets, debug_enabled)
        except SocketAPIError as err:
            # If writing packet fails, we don't know what state the frames
            # are in anymore and we have to close the connection
            _LOGGER.info("%s: Error writing packets: %s", self.log_name, err)
            self.report_fatal_error(err)
            raise

    def _add_message_callback_without_remove(
        self, on_message: Callable[[Any], None], msg_types: tuple[type[Any], ...]
    ) -> None:
        """Add a message callback without returning a remove callable."""
        message_handlers = self._message_handlers
        for msg_type in msg_types:
            if (handlers := message_handlers.get(msg_type)) is None:
                message_handlers[msg_type] = {on_message}
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
        message_handlers = self._message_handlers
        for msg_type in msg_types:
            handlers = message_handlers[msg_type]
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

    def _handle_timeout(self, fut: asyncio.Future[None]) -> None:
        """Handle a timeout."""
        if not fut.done():
            fut.set_exception(asyncio_TimeoutError)

    def _handle_complex_message(
        self,
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
        loop = self._loop
        # Unsafe to await between sending the message and registering the handler
        fut: asyncio.Future[None] = loop.create_future()
        responses: list[message.Message] = []
        handler = self._handle_complex_message
        on_message = partial(handler, fut, responses, do_append, do_stop)

        read_exception_futures = self._read_exception_futures
        self._add_message_callback_without_remove(on_message, msg_types)

        read_exception_futures.add(fut)
        # Now safe to await since we have registered the handler

        # We must not await without a finally or
        # the message could fail to be removed if the
        # the await is cancelled
        timeout_handle = loop.call_at(loop.time() + timeout, self._handle_timeout, fut)
        timeout_expired = False
        try:
            await fut
        except asyncio_TimeoutError as err:
            timeout_expired = True
            response_names = ", ".join(t.__name__ for t in msg_types)
            raise TimeoutAPIError(
                f"Timeout waiting for {response_names} after {timeout}s"
            ) from err
        finally:
            if not timeout_expired:
                timeout_handle.cancel()
            self._remove_message_callback(on_message, msg_types)
            read_exception_futures.discard(fut)

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
        if self._expected_disconnect is False and not self._fatal_exception:
            # Only log the first error
            _LOGGER.warning(
                "%s: Connection error occurred: %s",
                self.log_name,
                err or type(err),
                exc_info=not str(err),  # Log the full stack on empty error string
            )
        self._fatal_exception = err
        self._cleanup()

    def process_packet(self, msg_type_proto: _int, data: _bytes) -> None:
        """Process an incoming packet."""
        debug_enabled = self._debug_enabled
        if (klass := MESSAGE_TYPE_TO_PROTO.get(msg_type_proto)) is None:
            if debug_enabled:
                _LOGGER.debug(
                    "%s: Skipping unknown message type %s",
                    self.log_name,
                    msg_type_proto,
                )
            return

        try:
            msg = klass()
            # MergeFromString instead of ParseFromString since
            # ParseFromString will clear the message first and
            # the msg is already empty.
            msg.MergeFromString(data)
        except Exception as e:
            _LOGGER.error(
                "%s: Invalid protobuf message: type=%s data=%s: %s",
                self.log_name,
                klass.__name__,
                data,
                e,
                exc_info=True,
            )
            self.report_fatal_error(
                ProtocolAPIError(
                    f"Invalid protobuf message: type={klass.__name__} data={data!r}: {e}"
                )
            )
            raise

        msg_type = type(msg)

        if debug_enabled:
            _LOGGER.debug(
                "%s: Got message of type %s: %s",
                self.log_name,
                msg_type.__name__,
                msg,
            )

        if self._pong_timer is not None:
            # Any valid message from the remote cancels the pong timer
            # as we know the connection is still alive
            self._async_cancel_pong_timer()

        if self._send_pending_ping:
            # Any valid message from the remove cancels the pending ping
            # since we know the connection is still alive
            self._send_pending_ping = False

        if (handlers := self._message_handlers.get(msg_type)) is not None:
            handlers_copy = handlers.copy()
            for handler in handlers_copy:
                handler(msg)

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
        self.send_messages((DISCONNECT_RESPONSE_MESSAGE,))
        self._cleanup()

    def _handle_ping_request_internal(  # pylint: disable=unused-argument
        self, _msg: PingRequest
    ) -> None:
        """Handle a PingRequest."""
        self.send_messages((PING_RESPONSE_MESSAGE,))

    def _handle_get_time_request_internal(  # pylint: disable=unused-argument
        self, _msg: GetTimeRequest
    ) -> None:
        """Handle a GetTimeRequest."""
        resp = GetTimeResponse()
        resp.epoch_seconds = int(time.time())
        self.send_messages((resp,))

    async def disconnect(self) -> None:
        """Disconnect from the API."""
        if self._finish_connect_task:
            # Try to wait for the handshake to finish so we can send
            # a disconnect request. If it doesn't finish in time
            # we will just close the socket.
            _, pending = await asyncio.wait(
                [self._finish_connect_task], timeout=DISCONNECT_CONNECT_TIMEOUT
            )
            if pending:
                self._fatal_exception = TimeoutAPIError(
                    "Timed out waiting to finish connect before disconnecting"
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
            except APIConnectionError as err:
                _LOGGER.error("%s: disconnect request failed: %s", self.log_name, err)

        self._cleanup()

    def force_disconnect(self) -> None:
        """Forcefully disconnect from the API."""
        self._expected_disconnect = True
        if self._handshake_complete:
            # Still try to tell the esp to disconnect gracefully
            # but don't wait for it to finish
            try:
                self.send_messages((DISCONNECT_REQUEST_MESSAGE,))
            except APIConnectionError as err:
                _LOGGER.error(
                    "%s: Failed to send (forced) disconnect request: %s",
                    self.log_name,
                    err,
                )

        self._cleanup()

    def _get_message_handlers(
        self,
    ) -> dict[Any, set[Callable[[message.Message], None]]]:
        """Get the message handlers.

        This function is only used for testing for leaks.

        It has to be bound to the real instance to work since
        _message_handlers is not a public attribute.
        """
        return self._message_handlers
