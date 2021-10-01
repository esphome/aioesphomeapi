import asyncio
import base64
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
    ProtocolAPIError,
    RequiresEncryptionAPIError,
    ResolveAPIError,
    SocketAPIError,
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

    async def close(self) -> None:
        async with self._write_lock:
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
                raise SocketAPIError(f"Error while reading data: {err}") from err

    async def read_packet(self) -> Packet:
        if self._params.noise_psk is None:
            return await self._read_packet_plaintext()
        return await self._read_packet_noise()


class APIConnection:
    def __init__(
        self, params: ConnectionParams, on_stop: Callable[[], Awaitable[None]]
    ):
        self._params = params
        self.on_stop = on_stop
        self._stopped = False
        self._socket: Optional[socket.socket] = None
        self._frame_helper: Optional[APIFrameHelper] = None
        self._connected = False
        self._authenticated = False
        self._socket_connected = False
        self._state_lock = asyncio.Lock()
        self._api_version: Optional[APIVersion] = None

        self._message_handlers: List[Callable[[message.Message], None]] = []
        self.log_name = params.address
        self._ping_task: Optional[asyncio.Task[None]] = None
        self._read_exception_handlers: List[Callable[[Exception], None]] = []

    def _start_ping(self) -> None:
        async def func() -> None:
            while True:
                await asyncio.sleep(self._params.keepalive)

                try:
                    await self.ping()
                except APIConnectionError:
                    _LOGGER.info("%s: Ping Failed!", self.log_name)
                    await self._on_error()
                    return

        self._ping_task = asyncio.create_task(func())

    async def _close_socket(self) -> None:
        if not self._socket_connected:
            return
        if self._frame_helper is not None:
            await self._frame_helper.close()
            self._frame_helper = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        if self._ping_task is not None:
            self._ping_task.cancel()
            self._ping_task = None
        self._socket_connected = False
        self._connected = False
        self._authenticated = False
        _LOGGER.debug("%s: Closed socket", self.log_name)

    async def stop(self, force: bool = False) -> None:
        if self._stopped:
            return
        if self._connected and not force:
            try:
                await self._disconnect()
            except APIConnectionError:
                pass
        self._stopped = True
        await self._close_socket()
        await self.on_stop()

    async def _on_error(self) -> None:
        await self.stop(force=True)

    # pylint: disable=too-many-statements
    async def connect(self) -> None:
        if self._stopped:
            raise APIConnectionError(f"Connection is closed for {self.log_name}!")
        if self._connected:
            raise APIConnectionError(f"Already connected for {self.log_name}!")

        try:
            coro = hr.async_resolve_host(
                self._params.eventloop,
                self._params.address,
                self._params.port,
                self._params.zeroconf_instance,
            )
            addr = await asyncio.wait_for(coro, 30.0)
        except APIConnectionError as err:
            await self._on_error()
            raise err
        except asyncio.TimeoutError:
            await self._on_error()
            raise ResolveAPIError(
                f"Timeout while resolving IP address for {self.log_name}"
            )

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
            coro2 = self._params.eventloop.sock_connect(self._socket, sockaddr)
            await asyncio.wait_for(coro2, 30.0)
        except OSError as err:
            await self._on_error()
            raise SocketAPIError(f"Error connecting to {sockaddr}: {err}")
        except asyncio.TimeoutError:
            await self._on_error()
            raise SocketAPIError(f"Timeout while connecting to {sockaddr}")

        _LOGGER.debug("%s: Opened socket for", self._params.address)
        reader, writer = await asyncio.open_connection(sock=self._socket)
        self._frame_helper = APIFrameHelper(reader, writer, self._params)
        self._socket_connected = True

        try:
            await self._frame_helper.perform_handshake()
        except APIConnectionError:
            await self._on_error()
            raise

        self._params.eventloop.create_task(self.run_forever())

        hello = HelloRequest()
        hello.client_info = self._params.client_info
        try:
            resp = await self.send_message_await_response(hello, HelloResponse)
        except APIConnectionError:
            await self._on_error()
            raise
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
            await self._on_error()
            raise APIConnectionError("Incompatible API version.")
        self._connected = True

        self._start_ping()

    async def login(self) -> None:
        self._check_connected()
        if self._authenticated:
            raise APIConnectionError("Already logged in!")

        connect = ConnectRequest()
        if self._params.password is not None:
            connect.password = self._params.password
        resp = await self.send_message_await_response(connect, ConnectResponse)
        if resp.invalid_password:
            raise InvalidAuthAPIError("Invalid password!")

        self._authenticated = True

    def _check_connected(self) -> None:
        if not self._connected:
            raise APIConnectionError("Must be connected!")

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    async def send_message(self, msg: message.Message) -> None:
        if not self._socket_connected:
            raise APIConnectionError("Socket is not connected")

        for message_type, klass in MESSAGE_TYPE_TO_PROTO.items():
            if isinstance(msg, klass):
                break
        else:
            raise ValueError

        encoded = msg.SerializeToString()
        _LOGGER.debug("%s: Sending %s: %s", self._params.address, type(msg), str(msg))
        # pylint: disable=undefined-loop-variable
        assert self._frame_helper is not None
        await self._frame_helper.write_packet(
            Packet(
                type=message_type,
                data=encoded,
            )
        )

    async def send_message_callback_response(
        self, send_msg: message.Message, on_message: Callable[[Any], None]
    ) -> None:
        self._message_handlers.append(on_message)
        await self.send_message(send_msg)

    async def send_message_await_response_complex(
        self,
        send_msg: message.Message,
        do_append: Callable[[Any], bool],
        do_stop: Callable[[Any], bool],
        timeout: float = 10.0,
    ) -> List[Any]:
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
                fut.set_exception(exc)

        self._message_handlers.append(on_message)
        self._read_exception_handlers.append(on_read_exception)
        await self.send_message(send_msg)

        try:
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            if self._stopped:
                raise SocketAPIError("Disconnected while waiting for API response!")
            raise SocketAPIError("Timeout while waiting for API response!")
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

    async def _run_once(self) -> None:
        assert self._frame_helper is not None
        pkt = await self._frame_helper.read_packet()

        msg_type = pkt.type
        raw_msg = pkt.data
        if msg_type not in MESSAGE_TYPE_TO_PROTO:
            _LOGGER.debug(
                "%s: Skipping message type %s", self._params.address, msg_type
            )
            return

        msg = MESSAGE_TYPE_TO_PROTO[msg_type]()
        try:
            msg.ParseFromString(raw_msg)
        except Exception as e:
            raise ProtocolAPIError(f"Invalid protobuf message: {e}") from e
        _LOGGER.debug(
            "%s: Got message of type %s: %s", self._params.address, type(msg), msg
        )
        for msg_handler in self._message_handlers[:]:
            msg_handler(msg)
        await self._handle_internal_messages(msg)

    async def run_forever(self) -> None:
        while True:
            if self._frame_helper is None:
                # Socket closed
                break
            try:
                await self._run_once()
            except APIConnectionError as err:
                _LOGGER.info(
                    "%s: Error while reading incoming messages: %s",
                    self.log_name,
                    err,
                )
                for handler in self._read_exception_handlers[:]:
                    handler(err)
                await self._on_error()
                break
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning(
                    "%s: Unexpected error while reading incoming messages: %s",
                    self.log_name,
                    err,
                    exc_info=True,
                )
                for handler in self._read_exception_handlers[:]:
                    handler(err)
                await self._on_error()
                break

    async def _handle_internal_messages(self, msg: Any) -> None:
        if isinstance(msg, DisconnectRequest):
            await self.send_message(DisconnectResponse())
            await self.stop(force=True)
        elif isinstance(msg, PingRequest):
            await self.send_message(PingResponse())
        elif isinstance(msg, GetTimeRequest):
            resp = GetTimeResponse()
            resp.epoch_seconds = int(time.time())
            await self.send_message(resp)

    async def ping(self) -> None:
        self._check_connected()
        await self.send_message_await_response(PingRequest(), PingResponse)

    async def _disconnect(self) -> None:
        self._check_connected()

        try:
            await self.send_message_await_response(
                DisconnectRequest(), DisconnectResponse
            )
        except APIConnectionError:
            pass

    def _check_authenticated(self) -> None:
        if not self._authenticated:
            raise APIConnectionError("Must login first!")

    @property
    def api_version(self) -> Optional[APIVersion]:
        return self._api_version
