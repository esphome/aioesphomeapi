import asyncio
import logging
import socket
import time
from typing import Any, Callable, List, Optional, cast

import attr
from google.protobuf import message

import aioesphomeapi.api_pb2 as pb
from aioesphomeapi.core import APIConnectionError, MESSAGE_TYPE_TO_PROTO
from aioesphomeapi.model import APIVersion
from aioesphomeapi.util import _bytes_to_varuint, _varuint_to_bytes, resolve_ip_address

_LOGGER = logging.getLogger(__name__)


@attr.s
class ConnectionParams:
    eventloop = attr.ib(type=asyncio.events.AbstractEventLoop)
    address = attr.ib(type=str)
    port = attr.ib(type=int)
    password = attr.ib(type=Optional[str])
    client_info = attr.ib(type=str)
    keepalive = attr.ib(type=float)


class APIConnection:
    def __init__(self, params: ConnectionParams, on_stop):
        self._params = params
        self.on_stop = on_stop
        self._stopped = False
        self._socket = None  # type: Optional[socket.socket]
        self._socket_reader = None  # type: Optional[asyncio.StreamReader]
        self._socket_writer = None  # type: Optional[asyncio.StreamWriter]
        self._write_lock = asyncio.Lock()
        self._connected = False
        self._authenticated = False
        self._socket_connected = False
        self._state_lock = asyncio.Lock()
        self._api_version = None  # type: Optional[APIVersion]

        self._message_handlers = []  # type: List[Callable[[message], None]]

        self._running_task = None  # type: Optional[asyncio.Task]

    def _start_ping(self) -> None:
        async def func() -> None:
            while self._connected:
                await asyncio.sleep(self._params.keepalive)

                if not self._connected:
                    return

                try:
                    await self.ping()
                except APIConnectionError:
                    _LOGGER.info("%s: Ping Failed!", self._params.address)
                    await self._on_error()
                    return

        self._params.eventloop.create_task(func())

    async def _close_socket(self) -> None:
        if not self._socket_connected:
            return
        async with self._write_lock:
            self._socket_writer.close()
            self._socket_writer = None
            self._socket_reader = None
        if self._socket is not None:
            self._socket.close()
        self._socket_connected = False
        self._connected = False
        self._authenticated = False
        _LOGGER.debug("%s: Closed socket", self._params.address)

    async def stop(self, force: bool = False) -> None:
        if self._stopped:
            return
        if self._connected and not force:
            try:
                await self._disconnect()
            except APIConnectionError:
                pass
        self._stopped = True
        if self._running_task is not None:
            self._running_task.cancel()
        await self._close_socket()
        await self.on_stop()

    async def _on_error(self) -> None:
        await self.stop(force=True)

    async def connect(self) -> None:
        if self._stopped:
            raise APIConnectionError("Connection is closed!")
        if self._connected:
            raise APIConnectionError("Already connected!")

        try:
            coro = resolve_ip_address(self._params.eventloop, self._params.address,
                                      self._params.port)
            sockaddr = await asyncio.wait_for(coro, 30.0)
        except APIConnectionError as err:
            await self._on_error()
            raise err
        except asyncio.TimeoutError:
            await self._on_error()
            raise APIConnectionError("Timeout while resolving IP address")

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setblocking(False)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        _LOGGER.debug("%s: Connecting to %s:%s (%s)", self._params.address,
                      self._params.address, self._params.port, sockaddr)
        try:
            coro = self._params.eventloop.sock_connect(self._socket, sockaddr)
            await asyncio.wait_for(coro, 30.0)
        except OSError as err:
            await self._on_error()
            raise APIConnectionError("Error connecting to {}: {}".format(sockaddr, err))
        except asyncio.TimeoutError:
            await self._on_error()
            raise APIConnectionError("Timeout while connecting to {}".format(sockaddr))

        _LOGGER.debug("%s: Opened socket for", self._params.address)
        self._socket_reader, self._socket_writer = await asyncio.open_connection(sock=self._socket)
        self._socket_connected = True
        self._params.eventloop.create_task(self.run_forever())

        hello = pb.HelloRequest()
        hello.client_info = self._params.client_info
        try:
            resp = await self.send_message_await_response(hello, pb.HelloResponse)
        except APIConnectionError as err:
            await self._on_error()
            raise err
        _LOGGER.debug("%s: Successfully connected ('%s' API=%s.%s)",
                      self._params.address, resp.server_info, resp.api_version_major,
                      resp.api_version_minor)
        self._api_version = APIVersion(resp.api_version_major, resp.api_version_minor)
        if self._api_version.major > 2:
            _LOGGER.error("%s: Incompatible version %s! Closing connection",
                          self._api_version.major)
            await self._on_error()
            raise APIConnectionError("Incompatible API version.")
        self._connected = True

        self._start_ping()

    async def login(self) -> None:
        self._check_connected()
        if self._authenticated:
            raise APIConnectionError("Already logged in!")

        connect = pb.ConnectRequest()
        if self._params.password is not None:
            connect.password = self._params.password
        resp = await self.send_message_await_response(connect, pb.ConnectResponse)
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
        _LOGGER.debug("%s: Write: %s", self._params.address,
                      ' '.join('{:02X}'.format(x) for x in data))
        if not self._socket_connected:
            raise APIConnectionError("Socket is not connected")
        try:
            async with self._write_lock:
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
        req += _varuint_to_bytes(len(encoded))
        req += _varuint_to_bytes(message_type)
        req += encoded
        await self._write(req)

    async def send_message_callback_response(self, send_msg: message.Message,
                                             on_message: Callable[[Any], None]) -> None:
        self._message_handlers.append(on_message)
        await self.send_message(send_msg)

    async def send_message_await_response_complex(self, send_msg: message.Message,
                                                  do_append: Callable[[Any], bool],
                                                  do_stop: Callable[[Any], bool],
                                                  timeout: float = 5.0) -> List[Any]:
        fut = self._params.eventloop.create_future()
        responses = []

        def on_message(resp):
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

    async def send_message_await_response(self,
                                          send_msg: message.Message,
                                          response_type: Any, timeout: float = 5.0) -> Any:
        def is_response(msg):
            return isinstance(msg, response_type)

        res = await self.send_message_await_response_complex(
            send_msg, is_response, is_response, timeout=timeout)
        if len(res) != 1:
            raise APIConnectionError("Expected one result, got {}".format(len(res)))

        return res[0]

    async def _recv(self, amount: int) -> bytes:
        if amount == 0:
            return bytes()

        try:
            ret = await self._socket_reader.readexactly(amount)
        except (asyncio.IncompleteReadError, OSError, TimeoutError) as err:
            raise APIConnectionError("Error while receiving data: {}".format(err))

        return ret

    async def _recv_varint(self) -> int:
        raw = bytes()
        while not raw or raw[-1] & 0x80:
            raw += await self._recv(1)
        return cast(int, _bytes_to_varuint(raw))

    async def _run_once(self) -> None:
        preamble = await self._recv(1)
        if preamble[0] != 0x00:
            raise APIConnectionError("Invalid preamble")

        length = await self._recv_varint()
        msg_type = await self._recv_varint()

        raw_msg = await self._recv(length)
        if msg_type not in MESSAGE_TYPE_TO_PROTO:
            _LOGGER.debug("%s: Skipping message type %s", self._params.address, msg_type)
            return

        msg = MESSAGE_TYPE_TO_PROTO[msg_type]()
        try:
            msg.ParseFromString(raw_msg)
        except Exception as e:
            raise APIConnectionError("Invalid protobuf message: {}".format(e))
        _LOGGER.debug("%s: Got message of type %s: %s", self._params.address, type(msg), msg)
        for msg_handler in self._message_handlers[:]:
            msg_handler(msg)
        await self._handle_internal_messages(msg)

    async def run_forever(self) -> None:
        while True:
            try:
                await self._run_once()
            except APIConnectionError as err:
                _LOGGER.info("%s: Error while reading incoming messages: %s",
                             self._params.address, err)
                await self._on_error()
                break
            except Exception as err:
                _LOGGER.info("%s: Unexpected error while reading incoming messages: %s",
                             self._params.address, err)
                await self._on_error()
                break

    async def _handle_internal_messages(self, msg: Any) -> None:
        if isinstance(msg, pb.DisconnectRequest):
            await self.send_message(pb.DisconnectResponse())
            await self.stop(force=True)
        elif isinstance(msg, pb.PingRequest):
            await self.send_message(pb.PingResponse())
        elif isinstance(msg, pb.GetTimeRequest):
            resp = pb.GetTimeResponse()
            resp.epoch_seconds = int(time.time())
            await self.send_message(resp)

    async def ping(self) -> None:
        self._check_connected()
        await self.send_message_await_response(pb.PingRequest(), pb.PingResponse)

    async def _disconnect(self) -> None:
        self._check_connected()

        try:
            await self.send_message_await_response(pb.DisconnectRequest(), pb.DisconnectResponse)
        except APIConnectionError:
            pass

    def _check_authenticated(self) -> None:
        if not self._authenticated:
            raise APIConnectionError("Must login first!")

    @property
    def api_version(self) -> Optional[APIVersion]:
        return self._api_version
