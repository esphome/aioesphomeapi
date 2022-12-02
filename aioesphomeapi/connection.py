import asyncio
import enum
import logging
import socket
import time
from contextlib import suppress
from dataclasses import astuple, dataclass
from typing import Any, Callable, Coroutine, Dict, Iterable, List, Optional, Type

import async_timeout
from google.protobuf import message

import aioesphomeapi.host_resolver as hr

from ._frame_helper import (
    APIFrameHelper,
    APINoiseFrameHelper,
    APIPlaintextFrameHelper,
    Packet,
)
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
    InvalidAuthAPIError,
    PingFailedAPIError,
    ProtocolAPIError,
    ReadFailedAPIError,
    ResolveAPIError,
    SocketAPIError,
    SocketClosedAPIError,
    TimeoutAPIError,
)
from .model import APIVersion

_LOGGER = logging.getLogger(__name__)

BUFFER_SIZE = 1024 * 1024  # Set buffer limit to 1MB

INTERNAL_MESSAGE_TYPES = {GetTimeRequest, PingRequest, DisconnectRequest}

PROTO_TO_MESSAGE_TYPE = {v: k for k, v in MESSAGE_TYPE_TO_PROTO.items()}


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
    CONNECTED = 1
    CLOSED = 2


class APIConnection:
    """This class represents _one_ connection to a remote native API device.

    An instance of this class may only be used once, for every new connection
    a new instance should be established.
    """

    def __init__(
        self, params: ConnectionParams, on_stop: Callable[[], Coroutine[Any, Any, None]]
    ):
        self._params = params
        self.on_stop = on_stop
        self._on_stop_called = False
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
        self.log_name = params.address

        # Handlers currently subscribed to exceptions in the read task
        self._read_exception_handlers: List[Callable[[Exception], None]] = []

        self._ping_stop_event = asyncio.Event()

        self._to_process: asyncio.Queue[Optional[Packet]] = asyncio.Queue()

        self._process_task: Optional[asyncio.Task[None]] = None

        self._connect_lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task[None]] = None

    async def _cleanup(self) -> None:
        """Clean up all resources that have been allocated.

        Safe to call multiple times.
        """

        async def _do_cleanup() -> None:
            async with self._connect_lock:
                # Tell the process loop to stop
                self._to_process.put_nowait(None)

                if self._frame_helper is not None:
                    await self._frame_helper.close()
                    self._frame_helper = None

                if self._process_task is not None:
                    self._process_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await self._process_task
                    self._process_task = None

                if self._socket is not None:
                    self._socket.close()
                    self._socket = None

                if not self._on_stop_called and self._connect_complete:
                    # Ensure on_stop is called
                    asyncio.create_task(self.on_stop())
                    self._on_stop_called = True

                # Note: we don't explicitly cancel the ping/read task here
                # That's because if not written right the ping/read task could cancel
                # themself, effectively ending execution after _cleanup which may be unexpected
                self._ping_stop_event.set()

        if not self._cleanup_task or not self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(_do_cleanup())

    async def _connect_resolve_host(self) -> hr.AddrInfo:
        """Step 1 in connect process: resolve the address."""
        try:
            coro = hr.async_resolve_host(
                self._params.address,
                self._params.port,
                self._params.zeroconf_instance,
            )
            async with async_timeout.timeout(30.0):
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
            async with async_timeout.timeout(30.0):
                await coro
        except OSError as err:
            raise SocketAPIError(f"Error connecting to {sockaddr}: {err}") from err
        except asyncio.TimeoutError as err:
            raise SocketAPIError(f"Timeout while connecting to {sockaddr}") from err

        _LOGGER.debug("%s: Opened socket", self._params.address)

    async def _connect_init_frame_helper(self) -> None:
        """Step 3 in connect process: initialize the frame helper and init read loop."""
        reader, writer = await asyncio.open_connection(
            sock=self._socket, limit=BUFFER_SIZE
        )  # Set buffer limit to 1MB

        if self._params.noise_psk is None:
            self._frame_helper = APIPlaintextFrameHelper(reader, writer)
        else:
            fh = self._frame_helper = APINoiseFrameHelper(
                reader, writer, self._params.noise_psk
            )
            await fh.perform_handshake(self._params.expected_name)

        self._connection_state = ConnectionState.SOCKET_OPENED

        # Create read loop
        asyncio.create_task(self._read_loop())
        # Create process loop
        self._process_task = asyncio.create_task(self._process_loop())

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

        self._connection_state = ConnectionState.CONNECTED

    async def _connect_start_ping(self) -> None:
        """Step 5 in connect process: start the ping loop."""

        async def func() -> None:
            while True:
                if not self._is_socket_open:
                    return

                # Wait for keepalive seconds, or ping stop event, whichever happens first
                try:
                    async with async_timeout.timeout(self._params.keepalive):
                        await self._ping_stop_event.wait()
                except asyncio.TimeoutError:
                    pass

                # Re-check connection state
                if not self._is_socket_open:
                    return  # type: ignore[unreachable]

                try:
                    await self._ping()
                except TimeoutAPIError:
                    _LOGGER.info("%s: Ping timed out!", self.log_name)
                    await self._report_fatal_error(PingFailedAPIError())
                    return
                except APIConnectionError as err:
                    _LOGGER.info("%s: Ping Failed: %s", self.log_name, err)
                    await self._report_fatal_error(err)
                    return
                except Exception as err:  # pylint: disable=broad-except
                    _LOGGER.info(
                        "%s: Unexpected error during ping:",
                        self.log_name,
                        exc_info=True,
                    )
                    await self._report_fatal_error(err)
                    return

        asyncio.create_task(func())

    async def connect(self, *, login: bool) -> None:
        if self._connection_state != ConnectionState.INITIALIZED:
            raise ValueError(
                "Connection can only be used once, connection is not in init state"
            )

        async def _do_connect() -> None:
            addr = await self._connect_resolve_host()
            await self._connect_socket_connect(addr)
            await self._connect_init_frame_helper()
            await self._connect_hello()
            await self._connect_start_ping()
            if login:
                await self.login()

        # A connection lock must be created to avoid potential issues where
        # connect has succeeded but not yet returned, followed by a disconnect.
        # See esphome/aioesphomeapi#258 for more information
        async with self._connect_lock:
            try:
                # Allow 2 minutes for connect; this is only as a last measure
                # to protect from issues if some part of the connect process mistakenly
                # does not have a timeout
                async with async_timeout.timeout(120.0):
                    await _do_connect()
            except Exception:  # pylint: disable=broad-except
                # Always clean up the connection if an error occured during connect
                self._connection_state = ConnectionState.CLOSED
                await self._cleanup()
                raise

            self._connect_complete = True

    async def login(self) -> None:
        """Send a login (ConnectRequest) and await the response."""
        self._check_connected()
        if self._is_authenticated:
            raise APIConnectionError("Already logged in!")

        connect = ConnectRequest()
        if self._params.password is not None:
            connect.password = self._params.password
        try:
            resp = await self.send_message_await_response(connect, ConnectResponse)
        except TimeoutAPIError as err:
            # After a timeout for connect the connection can no longer be used
            # We don't know what state the device may be in after ConnectRequest
            # was already sent
            await self._report_fatal_error(err)
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

    async def send_message(self, msg: message.Message) -> None:
        """Send a protobuf message to the remote."""
        if not self._is_socket_open:
            raise APIConnectionError("Connection isn't established yet")

        message_type = PROTO_TO_MESSAGE_TYPE.get(type(msg))
        if not message_type:
            raise ValueError(f"Message type id not found for type {type(msg)}")
        encoded = msg.SerializeToString()
        _LOGGER.debug("%s: Sending %s: %s", self._params.address, type(msg), str(msg))

        frame_helper = self._frame_helper
        assert frame_helper is not None
        if not frame_helper.ready:
            await frame_helper.wait_for_ready()

        try:
            frame_helper.write_packet(
                Packet(
                    type=message_type,
                    data=encoded,
                )
            )
        except SocketAPIError as err:  # pylint: disable=broad-except
            # If writing packet fails, we don't know what state the frames
            # are in anymore and we have to close the connection
            await self._report_fatal_error(err)
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

    async def send_message_callback_response(
        self,
        send_msg: message.Message,
        on_message: Callable[[Any], None],
        msg_types: Iterable[Type[Any]],
    ) -> None:
        """Send a message to the remote and register the given message handler."""
        for msg_type in msg_types:
            self._message_handlers.setdefault(msg_type, []).append(on_message)
        try:
            await self.send_message(send_msg)
        except asyncio.CancelledError:
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
            await self.send_message(send_msg)
            async with async_timeout.timeout(timeout):
                await fut
        except asyncio.TimeoutError as err:
            raise TimeoutAPIError(
                f"Timeout waiting for response for {type(send_msg)} after {timeout}s"
            ) from err
        finally:
            with suppress(ValueError):
                for msg_type in msg_types:
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

    async def _report_fatal_error(self, err: Exception) -> None:
        """Report a fatal error that occured during an operation.

        This should only be called for errors that mean the connection
        can no longer be used.

        The connection will be closed, all exception handlers notified.
        This method does not log the error, the call site should do so.
        """
        self._connection_state = ConnectionState.CLOSED
        for handler in self._read_exception_handlers[:]:
            handler(err)
        await self._cleanup()

    async def _process_loop(self) -> None:
        to_process = self._to_process
        while True:
            try:
                pkt = await to_process.get()
            except RuntimeError:
                break

            if pkt is None:
                # Socket closed but task isn't cancelled yet
                break

            msg_type_proto = pkt.type
            if msg_type_proto not in MESSAGE_TYPE_TO_PROTO:
                _LOGGER.debug(
                    "%s: Skipping message type %s", self.log_name, msg_type_proto
                )
                continue

            msg = MESSAGE_TYPE_TO_PROTO[msg_type_proto]()
            try:
                msg.ParseFromString(pkt.data)
            except Exception as e:
                await self._report_fatal_error(
                    ProtocolAPIError(f"Invalid protobuf message: {e}")
                )
                raise

            msg_type = type(msg)

            _LOGGER.debug(
                "%s: Got message of type %s: %s", self.log_name, msg_type, msg
            )

            for handler in self._message_handlers.get(msg_type, [])[:]:
                handler(msg)

            # Pre-check the message type to avoid awaiting
            # since most messages are not internal messages
            if msg_type in INTERNAL_MESSAGE_TYPES:
                await self._handle_internal_messages(msg)

    async def _read_loop(self) -> None:
        frame_helper = self._frame_helper
        assert frame_helper is not None
        await frame_helper.wait_for_ready()
        to_process = self._to_process
        try:
            # Once its ready, we hold the lock for the duration of the
            # connection so we don't have to keep locking/unlocking
            async with frame_helper.read_lock:
                while True:
                    to_process.put_nowait(await frame_helper.read_packet_with_lock())
        except SocketClosedAPIError as err:
            # don't log with info, if closed the site that closed the connection should log
            if not self._is_socket_open:
                # If we expected the socket to be closed, don't log
                # the error.
                return
            _LOGGER.debug(
                "%s: Socket closed, stopping read loop",
                self.log_name,
            )
            await self._report_fatal_error(err)
        except APIConnectionError as err:
            _LOGGER.info(
                "%s: Error while reading incoming messages: %s",
                self.log_name,
                err,
            )
            await self._report_fatal_error(err)
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.warning(
                "%s: Unexpected error while reading incoming messages: %s",
                self.log_name,
                err,
                exc_info=True,
            )
            await self._report_fatal_error(err)

    async def _handle_internal_messages(self, msg: Any) -> None:
        if isinstance(msg, DisconnectRequest):
            await self.send_message(DisconnectResponse())
            self._connection_state = ConnectionState.CLOSED
            await self._cleanup()
        elif isinstance(msg, PingRequest):
            await self.send_message(PingResponse())
        elif isinstance(msg, GetTimeRequest):
            resp = GetTimeResponse()
            resp.epoch_seconds = int(time.time())
            await self.send_message(resp)

    async def _ping(self) -> None:
        self._check_connected()
        await self.send_message_await_response(PingRequest(), PingResponse)

    async def disconnect(self) -> None:
        if self._connection_state != ConnectionState.CONNECTED:
            # already disconnected
            return

        try:
            await self.send_message_await_response(
                DisconnectRequest(), DisconnectResponse
            )
        except APIConnectionError:
            pass

        self._connection_state = ConnectionState.CLOSED
        await self._cleanup()

    async def force_disconnect(self) -> None:
        self._connection_state = ConnectionState.CLOSED
        await self._cleanup()

    @property
    def api_version(self) -> Optional[APIVersion]:
        return self._api_version
