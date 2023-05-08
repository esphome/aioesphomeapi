import asyncio
import contextvars
import enum
import logging
import socket
import time
from contextlib import suppress
from dataclasses import astuple, dataclass
from typing import Any, Callable, Coroutine, Dict, Iterable, List, Optional, Type, Union

import async_timeout
from google.protobuf import message

import aioesphomeapi.host_resolver as hr

from ._frame_helper import APIFrameHelper, APINoiseFrameHelper, APIPlaintextFrameHelper
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

BUFFER_SIZE = 1024 * 1024  # Set buffer limit to 1MB


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

in_do_connect: contextvars.ContextVar[Optional[bool]] = contextvars.ContextVar(
    "in_do_connect"
)


@dataclass
class ConnectionParams:
    address: str
    port: int
    password: Optional[str]
    client_info: str
    keepalive: float
    zeroconf_instance: hr.ZeroconfInstanceType
    noise_psk: Optional[str]
    expected_name: Optional[str]


class ConnectionState(enum.Enum):
    # The connection is initialized, but connect() wasn't called yet
    INITIALIZED = 0
    # Internal state,
    SOCKET_OPENED = 1
    # The connection has been established, data can be exchanged
    CONNECTED = 2
    CLOSED = 3


class APIConnection:
    """This class represents _one_ connection to a remote native API device.

    An instance of this class may only be used once, for every new connection
    a new instance should be established.
    """

    def __init__(
        self,
        params: ConnectionParams,
        on_stop: Callable[[bool], Coroutine[Any, Any, None]],
        log_name: Optional[str] = None,
    ) -> None:
        self._params = params
        self.on_stop: Optional[Callable[[bool], Coroutine[Any, Any, None]]] = on_stop
        self._on_stop_task: Optional[asyncio.Task[None]] = None
        self._socket: Optional[socket.socket] = None
        self._frame_helper: Optional[APIFrameHelper] = None
        self._api_version: Optional[APIVersion] = None

        self._connection_state = ConnectionState.INITIALIZED
        self._is_authenticated = False
        # Store whether connect() has completed
        # Used so that on_stop is _not_ called if an error occurs during connect()
        self._connect_complete = False

        # Message handlers currently subscribed to incoming messages
        self._message_handlers: Dict[Any, List[Callable[[message.Message], None]]] = {}
        # The friendly name to show for this connection in the logs
        self.log_name = log_name or params.address

        # Handlers currently subscribed to exceptions in the read task
        self._read_exception_handlers: List[Callable[[Exception], None]] = []

        self._ping_timer: Optional[asyncio.TimerHandle] = None
        self._pong_timer: Optional[asyncio.TimerHandle] = None
        self._keep_alive_interval = params.keepalive
        self._keep_alive_timeout = params.keepalive * KEEP_ALIVE_TIMEOUT_RATIO

        self._connect_task: Optional[asyncio.Task[None]] = None
        self._fatal_exception: Optional[Exception] = None
        self._expected_disconnect = False

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
        # If we are being called from do_connect we
        # need to make sure we don't cancel the task
        # that called us
        if self._connect_task is not None and not in_do_connect.get(False):
            self._connect_task.cancel()
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

        _LOGGER.debug(
            "%s: Connecting to %s:%s (%s)",
            self.log_name,
            self._params.address,
            self._params.port,
            addr,
        )
        sockaddr = astuple(addr.sockaddr)

        try:
            coro = asyncio.get_event_loop().sock_connect(self._socket, sockaddr)
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
        fh: Union[APIPlaintextFrameHelper, APINoiseFrameHelper]
        loop = asyncio.get_event_loop()

        if self._params.noise_psk is None:
            _, fh = await loop.create_connection(
                lambda: APIPlaintextFrameHelper(
                    on_pkt=self._process_packet,
                    on_error=self._report_fatal_error,
                ),
                sock=self._socket,
            )
        else:
            _, fh = await loop.create_connection(
                lambda: APINoiseFrameHelper(
                    noise_psk=self._params.noise_psk,
                    expected_name=self._params.expected_name,
                    on_pkt=self._process_packet,
                    on_error=self._report_fatal_error,
                ),
                sock=self._socket,
            )

        self._frame_helper = fh
        self._connection_state = ConnectionState.SOCKET_OPENED
        try:
            async with async_timeout.timeout(HANDSHAKE_TIMEOUT):
                await fh.perform_handshake()
        except OSError as err:
            raise HandshakeAPIError(f"Handshake failed: {err}") from err
        except asyncio.TimeoutError as err:
            raise TimeoutAPIError("Handshake timed out") from err

    async def _connect_hello(self) -> None:
        """Step 4 in connect process: send hello and get api version."""
        hello = HelloRequest()
        hello.client_info = self._params.client_info
        hello.api_version_major = 1
        hello.api_version_minor = 7
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
        self._api_version = APIVersion(resp.api_version_major, resp.api_version_minor)
        if self._api_version.major > 2:
            _LOGGER.error(
                "%s: Incompatible version %s! Closing connection",
                self.log_name,
                self._api_version.major,
            )
            raise APIConnectionError("Incompatible API version.")

        if (
            self._params.expected_name is not None
            and resp.name != ""
            and resp.name != self._params.expected_name
        ):
            raise BadNameAPIError(
                f"Server sent a different name '{resp.name}'", resp.name
            )

    async def _connect_start_ping(self) -> None:
        """Step 5 in connect process: start the ping loop."""
        self._async_schedule_keep_alive(asyncio.get_running_loop())

    def _async_schedule_keep_alive(self, loop: asyncio.AbstractEventLoop) -> None:
        """Start the keep alive task."""
        self._ping_timer = loop.call_later(
            self._keep_alive_interval, self._async_send_keep_alive
        )

    def _async_send_keep_alive(self) -> None:
        """Send a keep alive message."""
        if not self._is_socket_open:
            return

        loop = asyncio.get_running_loop()
        self.send_message(PING_REQUEST_MESSAGE)

        if self._pong_timer is None:
            # Do not reset the timer if it's already set
            # since the only thing we want to reset the timer
            # is if we receive a pong.
            self._pong_timer = loop.call_later(
                self._keep_alive_timeout, self._async_pong_not_received
            )
        else:
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

        self._async_schedule_keep_alive(loop)

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

    async def connect(self, *, login: bool) -> None:
        if self._connection_state != ConnectionState.INITIALIZED:
            raise ValueError(
                "Connection can only be used once, connection is not in init state"
            )

        async def _do_connect() -> None:
            in_do_connect.set(True)
            addr = await self._connect_resolve_host()
            await self._connect_socket_connect(addr)
            await self._connect_init_frame_helper()
            await self._connect_hello()
            await self._connect_start_ping()
            if login:
                await self.login(check_connected=False)

        self._connect_task = asyncio.create_task(
            _do_connect(), name=f"{self.log_name}: aioesphomeapi do_connect"
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
            self._connection_state = ConnectionState.CLOSED
            self._cleanup()
            raise self._fatal_exception or APIConnectionError("Connection cancelled")
        except Exception:  # pylint: disable=broad-except
            # Always clean up the connection if an error occured during connect
            self._connection_state = ConnectionState.CLOSED
            self._cleanup()
            raise

        self._connect_task = None
        self._connection_state = ConnectionState.CONNECTED
        self._connect_complete = True

    async def login(self, check_connected: bool = True) -> None:
        """Send a login (ConnectRequest) and await the response."""
        if check_connected:
            # On first connect, we don't want to check if we're connected
            # because we don't set the connection state until after login
            # is complete
            self._check_connected()
        if self._is_authenticated:
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

        self._is_authenticated = True

    def _check_connected(self) -> None:
        if self._connection_state != ConnectionState.CONNECTED:
            raise APIConnectionError("Must be connected!")

    @property
    def _is_socket_open(self) -> bool:
        return self._connection_state in (
            ConnectionState.SOCKET_OPENED,
            ConnectionState.CONNECTED,
        )

    @property
    def is_connected(self) -> bool:
        return self._connection_state == ConnectionState.CONNECTED

    @property
    def is_authenticated(self) -> bool:
        return self.is_connected and self._is_authenticated

    def send_message(self, msg: message.Message) -> None:
        """Send a protobuf message to the remote."""
        if not self._is_socket_open:
            raise APIConnectionError(
                f"Connection isn't established yet ({self._connection_state})"
            )

        frame_helper = self._frame_helper
        assert frame_helper is not None
        message_type = PROTO_TO_MESSAGE_TYPE.get(type(msg))
        if not message_type:
            raise ValueError(f"Message type id not found for type {type(msg)}")
        encoded = msg.SerializeToString()
        _LOGGER.debug("%s: Sending %s: %s", self._params.address, type(msg), str(msg))

        try:
            frame_helper.write_packet(message_type, encoded)
        except SocketAPIError as err:  # pylint: disable=broad-except
            # If writing packet fails, we don't know what state the frames
            # are in anymore and we have to close the connection
            _LOGGER.info("%s: Error writing packet: %s", self.log_name, err)
            self._report_fatal_error(err)
            raise

    def add_message_callback(
        self, on_message: Callable[[Any], None], msg_types: Iterable[Type[Any]]
    ) -> Callable[[], None]:
        """Add a message callback."""
        for msg_type in msg_types:
            self._message_handlers.setdefault(msg_type, []).append(on_message)

        def unsub() -> None:
            for msg_type in msg_types:
                self._message_handlers[msg_type].remove(on_message)

        return unsub

    def remove_message_callback(
        self, on_message: Callable[[Any], None], msg_types: Iterable[Type[Any]]
    ) -> None:
        """Remove a message callback."""
        for msg_type in msg_types:
            self._message_handlers[msg_type].remove(on_message)

    def send_message_callback_response(
        self,
        send_msg: message.Message,
        on_message: Callable[[Any], None],
        msg_types: Iterable[Type[Any]],
    ) -> None:
        """Send a message to the remote and register the given message handler."""
        for msg_type in msg_types:
            self._message_handlers.setdefault(msg_type, []).append(on_message)
        try:
            self.send_message(send_msg)
        except (asyncio.CancelledError, Exception):
            for msg_type in msg_types:
                self._message_handlers[msg_type].remove(on_message)
            raise

    async def send_message_await_response_complex(
        self,
        send_msg: message.Message,
        do_append: Callable[[message.Message], bool],
        do_stop: Callable[[message.Message], bool],
        msg_types: Iterable[Type[Any]],
        timeout: float = 10.0,
    ) -> List[message.Message]:
        """Send a message to the remote and build up a list response.

        :param send_msg: The message (request) to send.
        :param do_append: Predicate to check if a received message is part of the response.
        :param do_stop: Predicate to check if a received message is the stop response.
        :param timeout: The maximum amount of time to wait for the stop response.

        :raises TimeoutAPIError: if a timeout occured
        """
        fut = asyncio.get_event_loop().create_future()
        responses = []

        def on_message(resp: message.Message) -> None:
            if fut.done():
                return
            if do_append(resp):
                responses.append(resp)
            if do_stop(resp):
                fut.set_result(responses)

        def on_read_exception(exc: Exception) -> None:
            if not fut.done():
                new_exc = exc
                if not isinstance(exc, APIConnectionError):
                    new_exc = ReadFailedAPIError("Read failed")
                    new_exc.__cause__ = exc
                fut.set_exception(new_exc)

        for msg_type in msg_types:
            self._message_handlers.setdefault(msg_type, []).append(on_message)
        self._read_exception_handlers.append(on_read_exception)
        # We must not await without a finally or
        # the message could fail to be removed if the
        # the await is cancelled

        try:
            self.send_message(send_msg)
            async with async_timeout.timeout(timeout):
                await fut
        except asyncio.TimeoutError as err:
            raise TimeoutAPIError(
                f"Timeout waiting for response for {type(send_msg)} after {timeout}s"
            ) from err
        finally:
            for msg_type in msg_types:
                with suppress(ValueError):
                    self._message_handlers[msg_type].remove(on_message)
            with suppress(ValueError):
                self._read_exception_handlers.remove(on_read_exception)

        return responses

    async def send_message_await_response(
        self, send_msg: message.Message, response_type: Any, timeout: float = 10.0
    ) -> Any:
        res = await self.send_message_await_response_complex(
            send_msg,
            lambda msg: True,  # we will only get responses of `response_type`
            lambda msg: True,  # we will only get responses of `response_type`
            (response_type,),
            timeout=timeout,
        )
        if len(res) != 1:
            raise APIConnectionError(f"Expected one result, got {len(res)}")

        return res[0]

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
        self._connection_state = ConnectionState.CLOSED
        for handler in self._read_exception_handlers[:]:
            handler(err)
        self._read_exception_handlers.clear()
        self._cleanup()

    def _process_packet(self, msg_type_proto: int, data: bytes) -> None:
        """Process a packet from the socket."""
        if not (class_ := MESSAGE_TYPE_TO_PROTO.get(msg_type_proto)):
            _LOGGER.debug("%s: Skipping message type %s", self.log_name, msg_type_proto)
            return

        msg = class_()
        try:
            # MergeFromString instead of ParseFromString since
            # ParseFromString will clear the message first and
            # the msg is already empty.
            msg.MergeFromString(data)
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

        _LOGGER.debug("%s: Got message of type %s: %s", self.log_name, msg_type, msg)

        if self._pong_timer:
            # Any valid message from the remote cancels the pong timer
            # as we know the connection is still alive
            self._async_cancel_pong_timer()

        for handler in self._message_handlers.get(msg_type, [])[:]:
            handler(msg)

        # Pre-check the message type to avoid awaiting
        # since most messages are not internal messages
        if msg_type not in INTERNAL_MESSAGE_TYPES:
            return

        if msg_type is DisconnectRequest:
            self.send_message(DisconnectResponse())
            self._connection_state = ConnectionState.CLOSED
            self._expected_disconnect = True
            self._cleanup()
        elif msg_type is PingRequest:
            self.send_message(PING_RESPONSE_MESSAGE)
        elif msg_type is GetTimeRequest:
            resp = GetTimeResponse()
            resp.epoch_seconds = int(time.time())
            self.send_message(resp)

    async def disconnect(self) -> None:
        """Disconnect from the API."""
        if self._connect_task:
            # Try to wait for the handshake to finish so we can send
            # a disconnect request. If it doesn't finish in time
            # we will just close the socket.
            await asyncio.wait([self._connect_task], timeout=5.0)

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
            except APIConnectionError:
                pass

        self._connection_state = ConnectionState.CLOSED
        self._cleanup()

    async def force_disconnect(self) -> None:
        self._connection_state = ConnectionState.CLOSED
        self._expected_disconnect = True
        self._cleanup()

    @property
    def api_version(self) -> Optional[APIVersion]:
        return self._api_version
