from __future__ import annotations

import asyncio
import contextvars
import enum
import logging
import socket
import time
from collections.abc import Coroutine, Iterable
from dataclasses import astuple, dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Callable

import async_timeout
from google.protobuf import message

import aioesphomeapi.host_resolver as hr

from ._frame_helper import APINoiseFrameHelper, APIPlaintextFrameHelper
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
)
from .model import APIVersion

_LOGGER = logging.getLogger(__name__)

BUFFER_SIZE = 1024 * 1024 * 2  # Set buffer limit to 2MB


INTERNAL_MESSAGE_TYPES = {GetTimeRequest, PingRequest, DisconnectRequest}

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

HANDSHAKE_TIMEOUT = 30.0
RESOLVE_TIMEOUT = 30.0
CONNECT_REQUEST_TIMEOUT = 30.0

# The connect timeout should be the maximum time we expect the esp to take
# to reboot and connect to the network/WiFi.
TCP_CONNECT_TIMEOUT = 60.0

# The maximum time for the whole connect process to complete
CONNECT_AND_SETUP_TIMEOUT = 120.0

# How long to wait for an existing connection to finish being
# setup when requesting a disconnect so we can try to disconnect
# gracefully without closing the socket out from under the
# the esp device
DISCONNECT_WAIT_CONNECT_TIMEOUT = 5.0


in_do_connect: contextvars.ContextVar[bool | None] = contextvars.ContextVar(
    "in_do_connect"
)


@dataclass
class ConnectionParams:
    address: str
    port: int
    password: str | None
    client_info: str
    keepalive: float
    zeroconf_instance: hr.ZeroconfInstanceType
    noise_psk: str | None
    expected_name: str | None


class ConnectionState(enum.Enum):
    # The connection is initialized, but connect() wasn't called yet
    INITIALIZED = 0
    # Internal state,
    SOCKET_OPENED = 1
    # The connection has been established, data can be exchanged
    CONNECTED = 2
    CLOSED = 3


OPEN_STATES = {ConnectionState.SOCKET_OPENED, ConnectionState.CONNECTED}


class APIConnection:
    """This class represents _one_ connection to a remote native API device.

    An instance of this class may only be used once, for every new connection
    a new instance should be established.
    """

    __slots__ = (
        "_params",
        "on_stop",
        "_on_stop_task",
        "_socket",
        "_frame_helper",
        "api_version",
        "_connection_state",
        "_connect_complete",
        "_message_handlers",
        "log_name",
        "_read_exception_futures",
        "_ping_timer",
        "_pong_timer",
        "_keep_alive_interval",
        "_keep_alive_timeout",
        "_connect_task",
        "_fatal_exception",
        "_expected_disconnect",
        "_loop",
        "_send_pending_ping",
        "is_connected",
        "is_authenticated",
        "_is_socket_open",
        "_debug_enabled",
    )

    def __init__(
        self,
        params: ConnectionParams,
        on_stop: Callable[[bool], Coroutine[Any, Any, None]],
        log_name: str | None = None,
    ) -> None:
        self._params = params
        self.on_stop: Callable[[bool], Coroutine[Any, Any, None]] | None = on_stop
        self._on_stop_task: asyncio.Task[None] | None = None
        self._socket: socket.socket | None = None
        self._frame_helper: None | (
            APINoiseFrameHelper | APIPlaintextFrameHelper
        ) = None
        self.api_version: APIVersion | None = None

        self._connection_state = ConnectionState.INITIALIZED
        # Store whether connect() has completed
        # Used so that on_stop is _not_ called if an error occurs during connect()
        self._connect_complete = False

        # Message handlers currently subscribed to incoming messages
        self._message_handlers: dict[Any, set[Callable[[message.Message], None]]] = {}
        # The friendly name to show for this connection in the logs
        self.log_name = log_name or params.address

        # futures currently subscribed to exceptions in the read task
        self._read_exception_futures: set[asyncio.Future[None]] = set()

        self._ping_timer: asyncio.TimerHandle | None = None
        self._pong_timer: asyncio.TimerHandle | None = None
        self._keep_alive_interval = params.keepalive
        self._keep_alive_timeout = params.keepalive * KEEP_ALIVE_TIMEOUT_RATIO

        self._connect_task: asyncio.Task[None] | None = None
        self._fatal_exception: Exception | None = None
        self._expected_disconnect = False
        self._send_pending_ping = False
        self._loop = asyncio.get_event_loop()
        self.is_connected = False
        self.is_authenticated = False
        self._is_socket_open = False
        self._debug_enabled = partial(_LOGGER.isEnabledFor, logging.DEBUG)

    @property
    def connection_state(self) -> ConnectionState:
        """Return the current connection state."""
        return self._connection_state

    def set_log_name(self, name: str) -> None:
        """Set the friendly log name for this connection."""
        self.log_name = name

    def _cleanup(self) -> None:
        """Clean up all resources that have been allocated.

        Safe to call multiple times.
        """
        _LOGGER.debug("Cleaning up connection to %s", self.log_name)
        for fut in self._read_exception_futures:
            if fut.done():
                continue
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
        if self._connect_task is not None and not in_do_connect.get(False):
            self._connect_task.cancel("Connection cleanup")
            self._connect_task = None

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

        if self.on_stop and self._connect_complete:

            def _remove_on_stop_task(_fut: asyncio.Future[None]) -> None:
                """Remove the stop task.

                We need to do this because the asyncio does not hold
                a strong reference to the task, so it can be garbage
                collected unexpectedly.
                """
                self._on_stop_task = None

            # Ensure on_stop is called only once
            self._on_stop_task = asyncio.create_task(
                self.on_stop(self._expected_disconnect),
                name=f"{self.log_name} aioesphomeapi connection on_stop",
            )
            self._on_stop_task.add_done_callback(_remove_on_stop_task)
            self.on_stop = None

    async def _connect_resolve_host(self) -> hr.AddrInfo:
        """Step 1 in connect process: resolve the address."""
        try:
            coro = hr.async_resolve_host(
                self._params.address,
                self._params.port,
                self._params.zeroconf_instance,
            )
            async with async_timeout.timeout(RESOLVE_TIMEOUT):
                return await coro
        except asyncio.TimeoutError as err:
            raise ResolveAPIError(
                f"Timeout while resolving IP address for {self.log_name}"
            ) from err

    async def _connect_socket_connect(self, addr: hr.AddrInfo) -> None:
        """Step 2 in connect process: connect the socket."""
        self._socket = socket.socket(
            family=addr.family, type=addr.type, proto=addr.proto
        )
        self._socket.setblocking(False)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Try to reduce the pressure on esphome device as it measures
        # ram in bytes and we measure ram in megabytes.
        try:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE)
        except OSError as err:
            _LOGGER.warning(
                "%s: Failed to set socket receive buffer size: %s",
                self.log_name,
                err,
            )

        if self._debug_enabled():
            _LOGGER.debug(
                "%s: Connecting to %s:%s (%s)",
                self.log_name,
                self._params.address,
                self._params.port,
                addr,
            )
        sockaddr = astuple(addr.sockaddr)

        try:
            coro = self._loop.sock_connect(self._socket, sockaddr)
            async with async_timeout.timeout(TCP_CONNECT_TIMEOUT):
                await coro
        except OSError as err:
            raise SocketAPIError(f"Error connecting to {sockaddr}: {err}") from err
        except asyncio.TimeoutError as err:
            raise SocketAPIError(f"Timeout while connecting to {sockaddr}") from err

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
        process_packet = self._process_packet_factory()

        if self._params.noise_psk is None:
            _, fh = await loop.create_connection(
                lambda: APIPlaintextFrameHelper(
                    on_pkt=process_packet,
                    on_error=self._report_fatal_error,
                    client_info=self._params.client_info,
                    log_name=self.log_name,
                ),
                sock=self._socket,
            )
        else:
            _, fh = await loop.create_connection(
                lambda: APINoiseFrameHelper(
                    noise_psk=self._params.noise_psk,
                    expected_name=self._params.expected_name,
                    on_pkt=process_packet,
                    on_error=self._report_fatal_error,
                    client_info=self._params.client_info,
                    log_name=self.log_name,
                ),
                sock=self._socket,
            )

        self._frame_helper = fh
        self._set_connection_state(ConnectionState.SOCKET_OPENED)
        try:
            await fh.perform_handshake(HANDSHAKE_TIMEOUT)
        except OSError as err:
            raise HandshakeAPIError(f"Handshake failed: {err}") from err
        except asyncio.TimeoutError as err:
            raise TimeoutAPIError("Handshake timed out") from err

    async def _connect_hello(self) -> None:
        """Step 4 in connect process: send hello and get api version."""
        hello = HelloRequest()
        hello.client_info = self._params.client_info
        hello.api_version_major = 1
        hello.api_version_minor = 9
        try:
            resp = await self.send_message_await_response(hello, HelloResponse)
        except TimeoutAPIError as err:
            raise TimeoutAPIError("Hello timed out") from err

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
            raise APIConnectionError("Incompatible API version.")

        self.api_version = api_version
        expected_name = self._params.expected_name
        received_name = resp.name
        if (
            expected_name is not None
            and received_name != ""
            and received_name != expected_name
        ):
            raise BadNameAPIError(
                f"Expected '{expected_name}' but server sent "
                f"a different name: '{received_name}'",
                received_name,
            )

    def _async_schedule_keep_alive(self, now: float) -> None:
        """Start the keep alive task."""
        self._send_pending_ping = True
        self._ping_timer = self._loop.call_at(
            now + self._keep_alive_interval, self._async_send_keep_alive
        )

    def _async_send_keep_alive(self) -> None:
        """Send a keep alive message."""
        if not self._is_socket_open:
            return

        loop = self._loop
        now = loop.time()

        if self._send_pending_ping:
            self.send_message(PING_REQUEST_MESSAGE)
            if self._pong_timer is None:
                # Do not reset the timer if it's already set
                # since the only thing we want to reset the timer
                # is if we receive a pong.
                self._pong_timer = loop.call_at(
                    now + self._keep_alive_timeout, self._async_pong_not_received
                )
            elif self._debug_enabled():
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
        if not self._is_socket_open:
            return
        _LOGGER.debug(
            "%s: Ping response not received after %s seconds",
            self.log_name,
            self._keep_alive_timeout,
        )
        self._report_fatal_error(
            PingFailedAPIError(
                f"Ping response not received after {self._keep_alive_timeout} seconds"
            )
        )

    async def _do_connect(self, login: bool) -> None:
        """Do the actual connect process."""
        in_do_connect.set(True)
        addr = await self._connect_resolve_host()
        await self._connect_socket_connect(addr)
        await self._connect_init_frame_helper()
        await self._connect_hello()
        if login:
            await self.login(check_connected=False)
        self._async_schedule_keep_alive(self._loop.time())

    async def connect(self, *, login: bool) -> None:
        if self._connection_state != ConnectionState.INITIALIZED:
            raise ValueError(
                "Connection can only be used once, connection is not in init state"
            )
        self._connect_task = asyncio.create_task(
            self._do_connect(login), name=f"{self.log_name}: aioesphomeapi do_connect"
        )
        try:
            # Allow 2 minutes for connect and setup; this is only as a last measure
            # to protect from issues if some part of the connect process mistakenly
            # does not have a timeout
            async with async_timeout.timeout(CONNECT_AND_SETUP_TIMEOUT):
                await self._connect_task
        except asyncio.CancelledError:
            # If the task was cancelled, we need to clean up the connection
            # and raise the CancelledError
            self._set_connection_state(ConnectionState.CLOSED)
            self._cleanup()
            raise self._fatal_exception or APIConnectionError("Connection cancelled")
        except Exception:  # pylint: disable=broad-except
            # Always clean up the connection if an error occurred during connect
            self._set_connection_state(ConnectionState.CLOSED)
            self._cleanup()
            raise

        self._connect_task = None
        self._set_connection_state(ConnectionState.CONNECTED)
        self._connect_complete = True

    def _set_connection_state(self, state: ConnectionState) -> None:
        """Set the connection state and log the change."""
        self._connection_state = state
        self.is_connected = state == ConnectionState.CONNECTED
        self._is_socket_open = state in OPEN_STATES

    async def login(self, check_connected: bool = True) -> None:
        """Send a login (ConnectRequest) and await the response."""
        if check_connected and self.is_connected:
            # On first connect, we don't want to check if we're connected
            # because we don't set the connection state until after login
            # is complete
            raise APIConnectionError("Must be connected!")
        if self.is_authenticated:
            raise APIConnectionError("Already logged in!")

        connect = ConnectRequest()
        if self._params.password is not None:
            connect.password = self._params.password
        try:
            resp = await self.send_message_await_response(
                connect, ConnectResponse, timeout=CONNECT_REQUEST_TIMEOUT
            )
        except TimeoutAPIError as err:
            # After a timeout for connect the connection can no longer be used
            # We don't know what state the device may be in after ConnectRequest
            # was already sent
            _LOGGER.debug("%s: Login timed out", self.log_name)
            self._report_fatal_error(err)
            raise

        if resp.invalid_password:
            raise InvalidAuthAPIError("Invalid password!")

        self.is_authenticated = True

    def send_message(self, msg: message.Message) -> None:
        """Send a protobuf message to the remote."""
        if not self._is_socket_open:
            if in_do_connect.get(False):
                # If we are in the do_connect task, we can't raise an error
                # because it would obscure the original exception (ie encrypt error).
                _LOGGER.debug("%s: Connection isn't established yet", self.log_name)
                return
            raise ConnectionNotEstablishedAPIError(
                f"Connection isn't established yet ({self._connection_state})"
            )

        if not (message_type := PROTO_TO_MESSAGE_TYPE.get(type(msg))):
            raise ValueError(f"Message type id not found for type {type(msg)}")

        if self._debug_enabled():
            _LOGGER.debug("%s: Sending %s: %s", self.log_name, type(msg).__name__, msg)

        if TYPE_CHECKING:
            assert self._frame_helper is not None

        encoded = msg.SerializeToString()
        try:
            self._frame_helper.write_packet(message_type, encoded)
        except SocketAPIError as err:
            # If writing packet fails, we don't know what state the frames
            # are in anymore and we have to close the connection
            _LOGGER.info("%s: Error writing packet: %s", self.log_name, err)
            self._report_fatal_error(err)
            raise

    def add_message_callback(
        self, on_message: Callable[[Any], None], msg_types: Iterable[type[Any]]
    ) -> Callable[[], None]:
        """Add a message callback."""
        message_handlers = self._message_handlers
        for msg_type in msg_types:
            message_handlers.setdefault(msg_type, set()).add(on_message)
        return partial(self._remove_message_callback, on_message, msg_types)

    def _remove_message_callback(
        self, on_message: Callable[[Any], None], msg_types: Iterable[type[Any]]
    ) -> None:
        """Remove a message callback."""
        message_handlers = self._message_handlers
        for msg_type in msg_types:
            message_handlers[msg_type].discard(on_message)

    def send_message_callback_response(
        self,
        send_msg: message.Message,
        on_message: Callable[[Any], None],
        msg_types: Iterable[type[Any]],
    ) -> Callable[[], None]:
        """Send a message to the remote and register the given message handler."""
        self.send_message(send_msg)
        # Since we do not return control to the event loop (no awaits)
        # between sending the message and registering the handler
        # we can be sure that we will not miss any messages even though
        # we register the handler after sending the message
        for msg_type in msg_types:
            self._message_handlers.setdefault(msg_type, set()).add(on_message)
        return partial(self._remove_message_callback, on_message, msg_types)

    def _handle_timeout(self, fut: asyncio.Future[None]) -> None:
        """Handle a timeout."""
        if fut.done():
            return
        fut.set_exception(asyncio.TimeoutError)

    def _handle_complex_message(
        self,
        fut: asyncio.Future[None],
        responses: list[message.Message],
        do_append: Callable[[message.Message], bool] | None,
        do_stop: Callable[[message.Message], bool] | None,
        resp: message.Message,
    ) -> None:
        """Handle a message that is part of a response."""
        if fut.done():
            return
        if do_append is None or do_append(resp):
            responses.append(resp)
        if do_stop is None or do_stop(resp):
            fut.set_result(None)

    async def send_message_await_response_complex(  # pylint: disable=too-many-locals
        self,
        send_msg: message.Message,
        do_append: Callable[[message.Message], bool] | None,
        do_stop: Callable[[message.Message], bool] | None,
        msg_types: Iterable[type[Any]],
        timeout: float = 10.0,
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

        self.send_message(send_msg)
        loop = self._loop
        # Unsafe to await between sending the message and registering the handler
        fut: asyncio.Future[None] = loop.create_future()
        responses: list[message.Message] = []
        on_message = partial(
            self._handle_complex_message, fut, responses, do_append, do_stop
        )

        message_handlers = self._message_handlers
        read_exception_futures = self._read_exception_futures
        for msg_type in msg_types:
            message_handlers.setdefault(msg_type, set()).add(on_message)

        read_exception_futures.add(fut)
        # Now safe to await since we have registered the handler

        # We must not await without a finally or
        # the message could fail to be removed if the
        # the await is cancelled
        timeout_handle = loop.call_at(loop.time() + timeout, self._handle_timeout, fut)
        timeout_expired = False
        try:
            await fut
        except asyncio.TimeoutError as err:
            timeout_expired = True
            raise TimeoutAPIError(
                f"Timeout waiting for response for {type(send_msg)} after {timeout}s"
            ) from err
        finally:
            if not timeout_expired:
                timeout_handle.cancel()
            for msg_type in msg_types:
                message_handlers[msg_type].discard(on_message)
            read_exception_futures.discard(fut)

        return responses

    async def send_message_await_response(
        self, send_msg: message.Message, response_type: Any, timeout: float = 10.0
    ) -> Any:
        [response] = await self.send_message_await_response_complex(
            send_msg,
            None,  # we will only get responses of `response_type`
            None,  # we will only get responses of `response_type`
            (response_type,),
            timeout=timeout,
        )
        return response

    def _report_fatal_error(self, err: Exception) -> None:
        """Report a fatal error that occurred during an operation.

        This should only be called for errors that mean the connection
        can no longer be used.

        The connection will be closed, all exception handlers notified.
        This method does not log the error, the call site should do so.
        """
        if not self._expected_disconnect and not self._fatal_exception:
            # Only log the first error
            _LOGGER.warning(
                "%s: Connection error occurred: %s",
                self.log_name,
                err or type(err),
                exc_info=not str(err),  # Log the full stack on empty error string
            )
        self._fatal_exception = err
        self._set_connection_state(ConnectionState.CLOSED)
        self._cleanup()

    def _process_packet_factory(self) -> Callable[[int, bytes], None]:
        """Factory to make a packet processor."""
        message_type_to_proto = MESSAGE_TYPE_TO_PROTO
        debug_enabled = self._debug_enabled
        message_handlers_get = self._message_handlers.get
        internal_message_types = INTERNAL_MESSAGE_TYPES

        def _process_packet(msg_type_proto: int, data: bytes) -> None:
            """Process a packet from the socket."""
            try:
                msg = message_type_to_proto[msg_type_proto]()
                # MergeFromString instead of ParseFromString since
                # ParseFromString will clear the message first and
                # the msg is already empty.
                msg.MergeFromString(data)
            except KeyError:
                _LOGGER.debug(
                    "%s: Skipping message type %s",
                    self.log_name,
                    msg_type_proto,
                )
                return
            except Exception as e:
                _LOGGER.info(
                    "%s: Invalid protobuf message: type=%s data=%s: %s",
                    self.log_name,
                    msg_type_proto,
                    data,
                    e,
                    exc_info=True,
                )
                self._report_fatal_error(
                    ProtocolAPIError(
                        f"Invalid protobuf message: type={msg_type_proto} data={data!r}: {e}"
                    )
                )
                raise

            msg_type = type(msg)

            if debug_enabled():
                _LOGGER.debug(
                    "%s: Got message of type %s: %s",
                    self.log_name,
                    msg_type.__name__,
                    msg,
                )

            if self._pong_timer:
                # Any valid message from the remote cancels the pong timer
                # as we know the connection is still alive
                self._async_cancel_pong_timer()

            if self._send_pending_ping:
                # Any valid message from the remove cancels the pending ping
                # since we know the connection is still alive
                self._send_pending_ping = False

            if handlers := message_handlers_get(msg_type):
                for handler in handlers.copy():
                    handler(msg)

            # Pre-check the message type to avoid awaiting
            # since most messages are not internal messages
            if msg_type not in internal_message_types:
                return

            if msg_type is DisconnectRequest:
                self.send_message(DisconnectResponse())
                self._set_connection_state(ConnectionState.CLOSED)
                self._expected_disconnect = True
                self._cleanup()
            elif msg_type is PingRequest:
                self.send_message(PING_RESPONSE_MESSAGE)
            elif msg_type is GetTimeRequest:
                resp = GetTimeResponse()
                resp.epoch_seconds = int(time.time())
                self.send_message(resp)

        return _process_packet

    async def disconnect(self) -> None:
        """Disconnect from the API."""
        if self._connect_task:
            # Try to wait for the handshake to finish so we can send
            # a disconnect request. If it doesn't finish in time
            # we will just close the socket.
            _, pending = await asyncio.wait([self._connect_task], timeout=5.0)
            if pending:
                _LOGGER.debug(
                    "%s: Connect task didn't finish before disconnect",
                    self.log_name,
                )

        self._expected_disconnect = True
        if self._is_socket_open and self._frame_helper:
            # We still want to send a disconnect request even
            # if the hello phase isn't finished to ensure we
            # the esp will clean up the connection as soon
            # as possible.
            try:
                await self.send_message_await_response(
                    DisconnectRequest(), DisconnectResponse
                )
            except APIConnectionError as err:
                _LOGGER.error(
                    "%s: Failed to send disconnect request: %s", self.log_name, err
                )

        self._set_connection_state(ConnectionState.CLOSED)
        self._cleanup()

    async def force_disconnect(self) -> None:
        """Forcefully disconnect from the API."""
        self._expected_disconnect = True
        if self._is_socket_open and self._frame_helper:
            # Still try to tell the esp to disconnect gracefully
            # but don't wait for it to finish
            try:
                self.send_message(DisconnectRequest())
            except APIConnectionError as err:
                _LOGGER.error(
                    "%s: Failed to send (forced) disconnect request: %s",
                    self.log_name,
                    err,
                )

        self._set_connection_state(ConnectionState.CLOSED)
        self._cleanup()
