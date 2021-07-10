import asyncio
import logging
import socket
import time
from dataclasses import astuple, dataclass
from typing import Any, Awaitable, Callable, List, Optional, cast

from google.protobuf import message

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
from .core import MESSAGE_TYPE_TO_PROTO, APIConnectionError
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


class APIConnection:
    def __init__(
        self, params: ConnectionParams, on_stop: Callable[[], Awaitable[None]]
    ):
        self._params = params
        self.on_stop = on_stop
        self._stopped = False
        self._socket: Optional[socket.socket] = None
        self._socket_reader: Optional[asyncio.StreamReader] = None
        self._socket_writer: Optional[asyncio.StreamWriter] = None
        self._write_lock = asyncio.Lock()
        self._connected = False
        self._authenticated = False
        self._socket_connected = False
        self._state_lock = asyncio.Lock()
        self._api_version: Optional[APIVersion] = None

        self._message_handlers: List[Callable[[message.Message], None]] = []
        self.log_name = params.address

    def _start_ping(self) -> None:
        async def func() -> None:
            while self._connected:
                await asyncio.sleep(self._params.keepalive)

                if not self._connected:
                    return

                try:
                    await self.ping()
                except APIConnectionError:
                    _LOGGER.info("%s: Ping Failed!", self.log_name)
                    await self._on_error()
                    return

        self._params.eventloop.create_task(func())

    async def _close_socket(self) -> None:
        if not self._socket_connected:
            return
        async with self._write_lock:
            if self._socket_writer is not None:
                self._socket_writer.close()
            self._socket_writer = None
            self._socket_reader = None
        if self._socket is not None:
            self._socket.close()
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
            raise APIConnectionError(
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
            raise APIConnectionError(f"Error connecting to {sockaddr}: {err}")
        except asyncio.TimeoutError:
            await self._on_error()
            raise APIConnectionError(f"Timeout while connecting to {sockaddr}")

        _LOGGER.debug("%s: Opened socket for", self._params.address)
        self._socket_reader, self._socket_writer = await asyncio.open_connection(
            sock=self._socket
        )
        self._socket_connected = True
        self._params.eventloop.create_task(self.run_forever())

        hello = HelloRequest()
        hello.client_info = self._params.client_info
        try:
            resp = await self.send_message_await_response(hello, HelloResponse)
        except APIConnectionError as err:
            await self._on_error()
            raise err
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
            raise APIConnectionError("Invalid password!")

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

    async def _write(self, data: bytes) -> None:
        # _LOGGER.debug("%s: Write: %s", self._params.address,
        #               ' '.join('{:02X}'.format(x) for x in data))
        if not self._socket_connected:
            raise APIConnectionError("Socket is not connected")
        try:
            async with self._write_lock:
                if self._socket_writer is not None:
                    self._socket_writer.write(data)
                    await self._socket_writer.drain()
        except OSError as err:
            await self._on_error()
            raise APIConnectionError("Error while writing data: {}".format(err))

    async def send_message(self, msg: message.Message) -> None:
        for message_type, klass in MESSAGE_TYPE_TO_PROTO.items():
            if isinstance(msg, klass):
                break
        else:
            raise ValueError

        encoded = msg.SerializeToString()
        _LOGGER.debug("%s: Sending %s: %s", self._params.address, type(msg), str(msg))
        req = bytes([0])
        req += varuint_to_bytes(len(encoded))
        # pylint: disable=undefined-loop-variable
        req += varuint_to_bytes(message_type)
        req += encoded
        await self._write(req)

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
        timeout: float = 5.0,
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

        self._message_handlers.append(on_message)
        await self.send_message(send_msg)

        try:
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            if self._stopped:
                raise APIConnectionError("Disconnected while waiting for API response!")
            raise APIConnectionError("Timeout while waiting for API response!")

        try:
            self._message_handlers.remove(on_message)
        except ValueError:
            pass

        return responses

    async def send_message_await_response(
        self, send_msg: message.Message, response_type: Any, timeout: float = 5.0
    ) -> Any:
        def is_response(msg: message.Message) -> bool:
            return isinstance(msg, response_type)

        res = await self.send_message_await_response_complex(
            send_msg, is_response, is_response, timeout=timeout
        )
        if len(res) != 1:
            raise APIConnectionError("Expected one result, got {}".format(len(res)))

        return res[0]

    async def _recv(self, amount: int) -> bytes:
        if amount == 0:
            return bytes()

        try:
            assert self._socket_reader is not None
            ret = await self._socket_reader.readexactly(amount)
        except (asyncio.IncompleteReadError, OSError, TimeoutError) as err:
            raise APIConnectionError("Error while receiving data: {}".format(err))

        return ret

    async def _recv_varint(self) -> int:
        raw = bytes()
        while not raw or raw[-1] & 0x80:
            raw += await self._recv(1)
        return cast(int, bytes_to_varuint(raw))

    async def _run_once(self) -> None:
        preamble = await self._recv(1)
        if preamble[0] != 0x00:
            raise APIConnectionError("Invalid preamble")

        length = await self._recv_varint()
        msg_type = await self._recv_varint()

        raw_msg = await self._recv(length)
        if msg_type not in MESSAGE_TYPE_TO_PROTO:
            _LOGGER.debug(
                "%s: Skipping message type %s", self._params.address, msg_type
            )
            return

        msg = MESSAGE_TYPE_TO_PROTO[msg_type]()
        try:
            msg.ParseFromString(raw_msg)
        except Exception as e:
            raise APIConnectionError("Invalid protobuf message: {}".format(e))
        _LOGGER.debug(
            "%s: Got message of type %s: %s", self._params.address, type(msg), msg
        )
        for msg_handler in self._message_handlers[:]:
            msg_handler(msg)
        await self._handle_internal_messages(msg)

    async def run_forever(self) -> None:
        while True:
            try:
                await self._run_once()
            except APIConnectionError as err:
                _LOGGER.info(
                    "%s: Error while reading incoming messages: %s",
                    self.log_name,
                    err,
                )
                await self._on_error()
                break
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.info(
                    "%s: Unexpected error while reading incoming messages: %s",
                    self.log_name,
                    err,
                )
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
