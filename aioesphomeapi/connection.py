import asyncio
import base64
import enum
import logging
import socket
import time
from contextlib import suppress
from dataclasses import astuple, dataclass
from typing import Any, Awaitable, Callable, List, Optional

from google.protobuf import message
from noise.connection import NoiseConnection  # type: ignore

import aioesphomeapi.host_resolver as hr

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
    HandshakeAPIError,
    InvalidAuthAPIError,
    InvalidEncryptionKeyAPIError,
    PingFailedAPIError,
    ProtocolAPIError,
    ReadFailedAPIError,
    RequiresEncryptionAPIError,
    ResolveAPIError,
    SocketAPIError,
    SocketClosedAPIError,
    TimeoutAPIError,
)
from .model import APIVersion
from .util import bytes_to_varuint, varuint_to_bytes

_LOGGER = logging.getLogger(__name__)


@dataclass
class ConnectionParams:
    eventloop: asyncio.events.AbstractEventLoop
    address: str
    port: int
    password: Optional[str]
    client_info: str
    keepalive: float
    zeroconf_instance: hr.ZeroconfInstanceType
    noise_psk: Optional[str]


@dataclass
class Packet:
    type: int
    data: bytes


class APIFrameHelper:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        params: ConnectionParams,
    ):
        self._reader = reader
        self._writer = writer
        self._params = params
        self._write_lock = asyncio.Lock()
        self._read_lock = asyncio.Lock()
        self._ready_event = asyncio.Event()
        self._proto: Optional[NoiseConnection] = None
        self._closed_event = asyncio.Event()

    async def close(self) -> None:
        self._closed_event.set()
        self._writer.close()

    async def _write_frame_noise(self, frame: bytes) -> None:
        try:
            async with self._write_lock:
                _LOGGER.debug("Sending frame %s", frame.hex())
                header = bytes(
                    [
                        0x01,
                        (len(frame) >> 8) & 0xFF,
                        len(frame) & 0xFF,
                    ]
                )
                self._writer.write(header + frame)
                await self._writer.drain()
        except OSError as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def _read_frame_noise(self) -> bytes:
        try:
            async with self._read_lock:
                header = await self._reader.readexactly(3)
                if header[0] != 0x01:
                    raise ProtocolAPIError(f"Marker byte invalid: {header[0]}")
                msg_size = (header[1] << 8) | header[2]
                frame = await self._reader.readexactly(msg_size)
        except (asyncio.IncompleteReadError, OSError, TimeoutError) as err:
            if (
                isinstance(err, asyncio.IncompleteReadError)
                and self._closed_event.is_set()
            ):
                raise SocketClosedAPIError(
                    f"Socket closed while reading data: {err}"
                ) from err
            raise SocketAPIError(f"Error while reading data: {err}") from err

        _LOGGER.debug("Received frame %s", frame.hex())
        return frame

    async def perform_handshake(self) -> None:
        if self._params.noise_psk is None:
            return
        await self._write_frame_noise(b"")  # ClientHello
        prologue = b"NoiseAPIInit" + b"\x00\x00"
        server_hello = await self._read_frame_noise()  # ServerHello
        if not server_hello:
            raise HandshakeAPIError("ServerHello is empty")
        chosen_proto = server_hello[0]
        if chosen_proto != 0x01:
            raise HandshakeAPIError(
                f"Unknown protocol selected by client {chosen_proto}"
            )

        self._proto = NoiseConnection.from_name(b"Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        self._proto.set_as_initiator()

        try:
            noise_psk_bytes = base64.b64decode(self._params.noise_psk)
        except ValueError:
            raise InvalidEncryptionKeyAPIError(
                f"Malformed PSK {self._params.noise_psk}, expected base64-encoded value"
            )
        if len(noise_psk_bytes) != 32:
            raise InvalidEncryptionKeyAPIError(
                f"Malformed PSK {self._params.noise_psk}, expected 32-bytes of base64 data"
            )

        self._proto.set_psks(noise_psk_bytes)
        self._proto.set_prologue(prologue)
        self._proto.start_handshake()

        _LOGGER.debug("Starting handshake...")
        do_write = True
        while not self._proto.handshake_finished:
            if do_write:
                msg = self._proto.write_message()
                await self._write_frame_noise(b"\x00" + msg)
            else:
                msg = await self._read_frame_noise()
                if not msg:
                    raise HandshakeAPIError("Handshake message too short")
                if msg[0] != 0:
                    explanation = msg[1:].decode()
                    if explanation == "Handshake MAC failure":
                        raise InvalidEncryptionKeyAPIError("Invalid encryption key")
                    raise HandshakeAPIError(f"Handshake failure: {explanation}")
                self._proto.read_message(msg[1:])

            do_write = not do_write

        _LOGGER.debug("Handshake complete!")
        self._ready_event.set()

    async def _write_packet_noise(self, packet: Packet) -> None:
        await self._ready_event.wait()
        padding = 0
        data = (
            bytes(
                [
                    (packet.type >> 8) & 0xFF,
                    (packet.type >> 0) & 0xFF,
                    (len(packet.data) >> 8) & 0xFF,
                    (len(packet.data) >> 0) & 0xFF,
                ]
            )
            + packet.data
            + b"\x00" * padding
        )
        assert self._proto is not None
        frame = self._proto.encrypt(data)
        await self._write_frame_noise(frame)

    async def _write_packet_plaintext(self, packet: Packet) -> None:
        data = b"\0"
        data += varuint_to_bytes(len(packet.data))
        data += varuint_to_bytes(packet.type)
        data += packet.data
        try:
            async with self._write_lock:
                _LOGGER.debug("Sending frame %s", data.hex())
                self._writer.write(data)
                await self._writer.drain()
        except OSError as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def write_packet(self, packet: Packet) -> None:
        if self._params.noise_psk is None:
            await self._write_packet_plaintext(packet)
        else:
            await self._write_packet_noise(packet)

    async def _read_packet_noise(self) -> Packet:
        await self._ready_event.wait()
        frame = await self._read_frame_noise()
        assert self._proto is not None
        msg = self._proto.decrypt(frame)
        if len(msg) < 4:
            raise ProtocolAPIError(f"Bad packet frame: {msg}")
        pkt_type = (msg[0] << 8) | msg[1]
        data_len = (msg[2] << 8) | msg[3]
        if data_len + 4 > len(msg):
            raise ProtocolAPIError(f"Bad data len: {data_len} vs {len(msg)}")
        data = msg[4 : 4 + data_len]
        return Packet(type=pkt_type, data=data)

    async def _read_packet_plaintext(self) -> Packet:
        async with self._read_lock:
            try:
                preamble = await self._reader.readexactly(1)
                if preamble[0] != 0x00:
                    if preamble[0] == 0x01:
                        raise RequiresEncryptionAPIError(
                            "Connection requires encryption"
                        )
                    raise ProtocolAPIError(f"Invalid preamble {preamble[0]:02x}")

                length = b""
                while not length or (length[-1] & 0x80) == 0x80:
                    length += await self._reader.readexactly(1)
                length_int = bytes_to_varuint(length)
                assert length_int is not None
                msg_type = b""
                while not msg_type or (msg_type[-1] & 0x80) == 0x80:
                    msg_type += await self._reader.readexactly(1)
                msg_type_int = bytes_to_varuint(msg_type)
                assert msg_type_int is not None

                raw_msg = b""
                if length_int != 0:
                    raw_msg = await self._reader.readexactly(length_int)
                return Packet(type=msg_type_int, data=raw_msg)
            except (asyncio.IncompleteReadError, OSError, TimeoutError) as err:
                if (
                    isinstance(err, asyncio.IncompleteReadError)
                    and self._closed_event.is_set()
                ):
                    raise SocketClosedAPIError(
                        f"Socket closed while reading data: {err}"
                    ) from err
                raise SocketAPIError(f"Error while reading data: {err}") from err

    async def read_packet(self) -> Packet:
        if self._params.noise_psk is None:
            return await self._read_packet_plaintext()
        return await self._read_packet_noise()


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
        self, params: ConnectionParams, on_stop: Callable[[], Awaitable[None]]
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
        self._message_handlers: List[Callable[[message.Message], None]] = []
        # The friendly name to show for this connection in the logs
        self.log_name = params.address

        # Handlers currently subscribed to exceptions in the read task
        self._read_exception_handlers: List[Callable[[Exception], None]] = []

        self._ping_stop_event = asyncio.Event()

    async def _cleanup(self) -> None:
        """Clean up all resources that have been allocated.

        Safe to call multiple times.
        """
        if self._frame_helper is not None:
            await self._frame_helper.close()
            self._frame_helper = None

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

    async def _connect_resolve_host(self) -> hr.AddrInfo:
        """Step 1 in connect process: resolve the address."""
        try:
            coro = hr.async_resolve_host(
                self._params.eventloop,
                self._params.address,
                self._params.port,
                self._params.zeroconf_instance,
            )
            return await asyncio.wait_for(coro, 30.0)
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

        _LOGGER.debug(
            "%s: Connecting to %s:%s (%s)",
            self.log_name,
            self._params.address,
            self._params.port,
            addr,
        )
        sockaddr = astuple(addr.sockaddr)

        try:
            coro = self._params.eventloop.sock_connect(self._socket, sockaddr)
            await asyncio.wait_for(coro, 30.0)
        except OSError as err:
            raise SocketAPIError(f"Error connecting to {sockaddr}: {err}") from err
        except asyncio.TimeoutError as err:
            raise SocketAPIError(f"Timeout while connecting to {sockaddr}") from err

        _LOGGER.debug("%s: Opened socket for", self._params.address)

    async def _connect_init_frame_helper(self) -> None:
        """Step 3 in connect process: initialize the frame helper and init read loop."""
        reader, writer = await asyncio.open_connection(sock=self._socket)

        self._frame_helper = APIFrameHelper(reader, writer, self._params)
        await self._frame_helper.perform_handshake()

        self._connection_state = ConnectionState.SOCKET_OPENED

        # Create read loop
        asyncio.create_task(self._read_loop())

    async def _connect_hello(self) -> None:
        """Step 4 in connect process: send hello and get api version."""
        hello = HelloRequest()
        hello.client_info = self._params.client_info
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

        self._connection_state = ConnectionState.CONNECTED

    async def _connect_start_ping(self) -> None:
        """Step 5 in connect process: start the ping loop."""

        async def func() -> None:
            while True:
                if not self._is_socket_open:
                    return

                # Wait for keepalive seconds, or ping stop event, whichever happens first
                try:
                    await asyncio.wait_for(
                        self._ping_stop_event.wait(), self._params.keepalive
                    )
                except asyncio.TimeoutError:
                    pass

                # Re-check connection state
                if not self._is_socket_open:
                    return

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

    async def connect(self) -> None:
        if self._connection_state != ConnectionState.INITIALIZED:
            raise ValueError(
                "Connection can only be used once, connection is not in init state"
            )

        try:
            addr = await self._connect_resolve_host()
            await self._connect_socket_connect(addr)
            await self._connect_init_frame_helper()
            await self._connect_hello()
            await self._connect_start_ping()
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

        for message_type, klass in MESSAGE_TYPE_TO_PROTO.items():
            if isinstance(msg, klass):
                break
        else:
            raise ValueError(f"Message type id not found for type {type(msg)}")

        encoded = msg.SerializeToString()
        _LOGGER.debug("%s: Sending %s: %s", self._params.address, type(msg), str(msg))

        try:
            assert self._frame_helper is not None
            # pylint: disable=undefined-loop-variable
            await self._frame_helper.write_packet(
                Packet(
                    type=message_type,
                    data=encoded,
                )
            )
        except Exception as err:  # pylint: disable=broad-except
            # If writing packet fails, we don't know what state the frames
            # are in anymore and we have to close the connection
            await self._report_fatal_error(err)
            raise

    async def send_message_callback_response(
        self, send_msg: message.Message, on_message: Callable[[Any], None]
    ) -> None:
        """Send a message to the remote and register the given message handler."""
        self._message_handlers.append(on_message)
        await self.send_message(send_msg)

    async def send_message_await_response_complex(
        self,
        send_msg: message.Message,
        do_append: Callable[[Any], bool],
        do_stop: Callable[[Any], bool],
        timeout: float = 10.0,
    ) -> List[Any]:
        """Send a message to the remote and build up a list response.

        :param send_msg: The message (request) to send.
        :param do_append: Predicate to check if a received message is part of the response.
        :param do_stop: Predicate to check if a received message is the stop response.
        :param timeout: The maximum amount of time to wait for the stop response.

        :raises TimeoutAPIError: if a timeout occured
        """
        fut = self._params.eventloop.create_future()
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

        self._message_handlers.append(on_message)
        self._read_exception_handlers.append(on_read_exception)
        await self.send_message(send_msg)

        try:
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as err:
            raise TimeoutAPIError(
                f"Timeout waiting for response for {send_msg}"
            ) from err
        finally:
            with suppress(ValueError):
                self._message_handlers.remove(on_message)
            with suppress(ValueError):
                self._read_exception_handlers.remove(on_read_exception)

        return responses

    async def send_message_await_response(
        self, send_msg: message.Message, response_type: Any, timeout: float = 10.0
    ) -> Any:
        def is_response(msg: message.Message) -> bool:
            return isinstance(msg, response_type)

        res = await self.send_message_await_response_complex(
            send_msg, is_response, is_response, timeout=timeout
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

    async def _read_once(self) -> None:
        assert self._frame_helper is not None
        pkt = await self._frame_helper.read_packet()

        msg_type = pkt.type
        raw_msg = pkt.data
        if msg_type not in MESSAGE_TYPE_TO_PROTO:
            _LOGGER.debug("%s: Skipping message type %s", self.log_name, msg_type)
            return

        msg = MESSAGE_TYPE_TO_PROTO[msg_type]()
        try:
            msg.ParseFromString(raw_msg)
        except Exception as e:
            raise ProtocolAPIError(f"Invalid protobuf message: {e}") from e
        _LOGGER.debug("%s: Got message of type %s: %s", self.log_name, type(msg), msg)
        for msg_handler in self._message_handlers[:]:
            msg_handler(msg)
        await self._handle_internal_messages(msg)

    async def _read_loop(self) -> None:
        while True:
            if not self._is_socket_open:
                # Socket closed but task isn't cancelled yet
                break
            try:
                await self._read_once()
            except SocketClosedAPIError as err:
                # don't log with info, if closed the site that closed the connection should log
                _LOGGER.debug(
                    "%s: Socket closed, stopping read loop",
                    self.log_name,
                )
                await self._report_fatal_error(err)
                break
            except APIConnectionError as err:
                _LOGGER.info(
                    "%s: Error while reading incoming messages: %s",
                    self.log_name,
                    err,
                )
                await self._report_fatal_error(err)
                break
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning(
                    "%s: Unexpected error while reading incoming messages: %s",
                    self.log_name,
                    err,
                    exc_info=True,
                )
                await self._report_fatal_error(err)
                break

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
