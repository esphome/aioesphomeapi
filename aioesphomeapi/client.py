import asyncio
import logging
import socket
import time
from typing import Any, Callable, List, Optional, Tuple, Union, cast, Dict

import attr
from google.protobuf import message

import aioesphomeapi.api_pb2 as pb

_LOGGER = logging.getLogger(__name__)


class APIConnectionError(Exception):
    pass


MESSAGE_TYPE_TO_PROTO = {
    1: pb.HelloRequest,
    2: pb.HelloResponse,
    3: pb.ConnectRequest,
    4: pb.ConnectResponse,
    5: pb.DisconnectRequest,
    6: pb.DisconnectResponse,
    7: pb.PingRequest,
    8: pb.PingResponse,
    9: pb.DeviceInfoRequest,
    10: pb.DeviceInfoResponse,
    11: pb.ListEntitiesRequest,
    12: pb.ListEntitiesBinarySensorResponse,
    13: pb.ListEntitiesCoverResponse,
    14: pb.ListEntitiesFanResponse,
    15: pb.ListEntitiesLightResponse,
    16: pb.ListEntitiesSensorResponse,
    17: pb.ListEntitiesSwitchResponse,
    18: pb.ListEntitiesTextSensorResponse,
    19: pb.ListEntitiesDoneResponse,
    20: pb.SubscribeStatesRequest,
    21: pb.BinarySensorStateResponse,
    22: pb.CoverStateResponse,
    23: pb.FanStateResponse,
    24: pb.LightStateResponse,
    25: pb.SensorStateResponse,
    26: pb.SwitchStateResponse,
    27: pb.TextSensorStateResponse,
    28: pb.SubscribeLogsRequest,
    29: pb.SubscribeLogsResponse,
    30: pb.CoverCommandRequest,
    31: pb.FanCommandRequest,
    32: pb.LightCommandRequest,
    33: pb.SwitchCommandRequest,
    34: pb.SubscribeServiceCallsRequest,
    35: pb.ServiceCallResponse,
    36: pb.GetTimeRequest,
    37: pb.GetTimeResponse,
    38: pb.SubscribeHomeAssistantStatesRequest,
    39: pb.SubscribeHomeAssistantStateResponse,
    40: pb.HomeAssistantStateResponse,
    41: pb.ListEntitiesServicesResponse,
    42: pb.ExecuteServiceRequest,
}


def _varuint_to_bytes(value: int) -> bytes:
    if value <= 0x7F:
        return bytes([value])

    ret = bytes()
    while value:
        temp = value & 0x7F
        value >>= 7
        if value:
            ret += bytes([temp | 0x80])
        else:
            ret += bytes([temp])

    return ret


def _bytes_to_varuint(value: bytes) -> Optional[int]:
    result = 0
    bitpos = 0
    for val in value:
        result |= (val & 0x7F) << bitpos
        bitpos += 7
        if (val & 0x80) == 0:
            return result
    return None


async def resolve_ip_address_getaddrinfo(eventloop: asyncio.events.AbstractEventLoop,
                                         host: str, port: int) -> Tuple[Any, ...]:
    try:
        res = await eventloop.getaddrinfo(host, port, family=socket.AF_INET,
                                          proto=socket.IPPROTO_TCP)
    except OSError as err:
        raise APIConnectionError("Error resolving IP address: {}".format(err))

    if not res:
        raise APIConnectionError("Error resolving IP address: No matches!")

    _, _, _, _, sockaddr = res[0]

    return sockaddr


async def resolve_ip_address(eventloop: asyncio.events.AbstractEventLoop,
                             host: str, port: int) -> Tuple[Any, ...]:
    try:
        return await resolve_ip_address_getaddrinfo(eventloop, host, port)
    except APIConnectionError as err:
        if host.endswith('.local'):
            from aioesphomeapi.host_resolver import resolve_host

            return await eventloop.run_in_executor(None, resolve_host, host), port
        raise err


# Wrap some types in attr classes to make them serializable
@attr.s
class DeviceInfo:
    uses_password = attr.ib(type=bool)
    name = attr.ib(type=str)
    mac_address = attr.ib(type=str)
    esphome_core_version = attr.ib(type=str)
    compilation_time = attr.ib(type=str)
    model = attr.ib(type=str)
    has_deep_sleep = attr.ib(type=bool)


@attr.s
class EntityInfo:
    object_id = attr.ib(type=str)
    key = attr.ib(type=int)
    name = attr.ib(type=str)
    unique_id = attr.ib(type=str)


@attr.s
class EntityState:
    key = attr.ib(type=int)


@attr.s
class BinarySensorInfo(EntityInfo):
    device_class = attr.ib(type=str)
    is_status_binary_sensor = attr.ib(type=bool)


@attr.s
class BinarySensorState(EntityState):
    state = attr.ib(type=bool)


@attr.s
class CoverInfo(EntityInfo):
    is_optimistic = attr.ib(type=bool)


COVER_STATE_OPEN = 0
COVER_SATE_CLOSED = 1
COVER_STATES = [COVER_STATE_OPEN, COVER_SATE_CLOSED]

COVER_COMMAND_OPEN = 0
COVER_COMMAND_CLOSE = 1
COVER_COMMAND_STOP = 2
COVER_COMMANDS = [COVER_COMMAND_OPEN, COVER_COMMAND_CLOSE, COVER_COMMAND_STOP]


@attr.s
class CoverState(EntityState):
    state = attr.ib(type=int, converter=int,
                    validator=attr.validators.in_(COVER_STATES))


@attr.s
class FanInfo(EntityInfo):
    supports_oscillation = attr.ib(type=bool)
    supports_speed = attr.ib(type=bool)


FAN_SPEED_LOW = 0
FAN_SPEED_MEDIUM = 1
FAN_SPEED_HIGH = 2
FAN_SPEEDS = [FAN_SPEED_LOW, FAN_SPEED_MEDIUM, FAN_SPEED_HIGH]


@attr.s
class FanState(EntityState):
    state = attr.ib(type=bool)
    oscillating = attr.ib(type=bool)
    speed = attr.ib(type=int, converter=int,
                    validator=attr.validators.in_(FAN_SPEEDS))


@attr.s
class LightInfo(EntityInfo):
    supports_brightness = attr.ib(type=bool)
    supports_rgb = attr.ib(type=bool)
    supports_white_value = attr.ib(type=bool)
    supports_color_temperature = attr.ib(type=bool)
    min_mireds = attr.ib(type=float)
    max_mireds = attr.ib(type=float)
    effects = attr.ib(type=List[str], converter=list)


@attr.s
class LightState(EntityState):
    state = attr.ib(type=bool)
    brightness = attr.ib(type=float)
    red = attr.ib(type=float)
    green = attr.ib(type=float)
    blue = attr.ib(type=float)
    white = attr.ib(type=float)
    color_temperature = attr.ib(type=float)
    effect = attr.ib(type=str)


@attr.s
class SensorInfo(EntityInfo):
    icon = attr.ib(type=str)
    unit_of_measurement = attr.ib(type=str)
    accuracy_decimals = attr.ib(type=int)


@attr.s
class SensorState(EntityState):
    state = attr.ib(type=float)


@attr.s
class SwitchInfo(EntityInfo):
    icon = attr.ib(type=str)
    optimistic = attr.ib(type=bool)


@attr.s
class SwitchState(EntityState):
    state = attr.ib(type=bool)


@attr.s
class TextSensorInfo(EntityInfo):
    icon = attr.ib(type=str)


@attr.s
class TextSensorState(EntityState):
    state = attr.ib(type=str)


COMPONENT_TYPE_TO_INFO = {
    'binary_sensor': BinarySensorInfo,
    'cover': CoverInfo,
    'fan': FanInfo,
    'light': LightInfo,
    'sensor': SensorInfo,
    'switch': SwitchInfo,
    'text_sensor': TextSensorInfo,
}


@attr.s
class ServiceCall:
    service = attr.ib(type=str)
    data = attr.ib(type=Dict[str, str], converter=dict)
    data_template = attr.ib(type=Dict[str, str], converter=dict)
    variables = attr.ib(type=Dict[str, str], converter=dict)


USER_SERVICE_ARG_BOOL = 0
USER_SERVICE_ARG_INT = 1
USER_SERVICE_ARG_FLOAT = 2
USER_SERVICE_ARG_STRING = 3
USER_SERVICE_ARG_TYPES = [
    USER_SERVICE_ARG_BOOL, USER_SERVICE_ARG_INT, USER_SERVICE_ARG_FLOAT, USER_SERVICE_ARG_STRING
]


def _attr_obj_from_dict(cls, **kwargs):
    return cls(**{key: kwargs[key] for key in attr.fields_dict(cls)})


@attr.s
class UserServiceArg:
    name = attr.ib(type=str)
    type_ = attr.ib(type=int, converter=int,
                    validator=attr.validators.in_(USER_SERVICE_ARG_TYPES))


@attr.s
class UserService:
    name = attr.ib(type=str)
    key = attr.ib(type=int)
    args = attr.ib(type=List[UserServiceArg], converter=list)

    @staticmethod
    def from_dict(dict_):
        args = []
        for arg in dict_.get('args', []):
            args.append(_attr_obj_from_dict(UserServiceArg, **arg))
        return UserService(
            name=dict_.get('name', ''),
            key=dict_.get('key', 0),
            args=args
        )

    def to_dict(self):
        return {
            'name': self.name,
            'key': self.key,
            'args': [attr.asdict(arg) for arg in self.args],
        }


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
        _LOGGER.debug("%s: Successfully connected to %s ('%s' API=%s.%s)",
                      self._params.address, self._params.address,
                      resp.server_info, resp.api_version_major, resp.api_version_minor)
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


class APIClient:
    def __init__(self, eventloop, address: str, port: int, password: str, *,
                 client_info: str = 'aioesphomeapi', keepalive: float = 15.0):
        self._params = ConnectionParams(
            eventloop=eventloop,
            address=address,
            port=port,
            password=password,
            client_info=client_info,
            keepalive=keepalive,
        )
        self._connection = None  # type: Optional[APIConnection]

    async def connect(self, on_stop=None, login=False):
        if self._connection is not None:
            raise APIConnectionError("Already connected!")

        connected = False
        stopped = False

        async def _on_stop():
            nonlocal stopped

            if stopped:
                return
            stopped = True
            self._connection = None
            if connected and on_stop is not None:
                await on_stop()

        self._connection = APIConnection(self._params, _on_stop)

        try:
            await self._connection.connect()
            if login:
                await self._connection.login()
        except APIConnectionError:
            await _on_stop()
            raise
        except Exception as e:
            await _on_stop()
            raise APIConnectionError("Unexpected error while connecting: {}".format(e))

        connected = True

    async def disconnect(self, force=False):
        if self._connection is None:
            return
        await self._connection.stop(force=force)

    def _check_connected(self):
        if self._connection is None:
            raise APIConnectionError("Not connected!")
        if not self._connection.is_connected:
            raise APIConnectionError("Connection not done!")

    def _check_authenticated(self):
        self._check_connected()
        if not self._connection.is_authenticated:
            raise APIConnectionError("Not authenticated!")

    async def device_info(self) -> DeviceInfo:
        self._check_connected()
        resp = await self._connection.send_message_await_response(
            pb.DeviceInfoRequest(), pb.DeviceInfoResponse)
        return DeviceInfo(
            uses_password=resp.uses_password,
            name=resp.name,
            mac_address=resp.mac_address,
            esphome_core_version=resp.esphome_core_version,
            compilation_time=resp.compilation_time,
            model=resp.model,
            has_deep_sleep=resp.has_deep_sleep,
        )

    async def list_entities_services(self) -> Tuple[List[Any], List[UserService]]:
        self._check_authenticated()
        response_types = {
            pb.ListEntitiesBinarySensorResponse: BinarySensorInfo,
            pb.ListEntitiesCoverResponse: CoverInfo,
            pb.ListEntitiesFanResponse: FanInfo,
            pb.ListEntitiesLightResponse: LightInfo,
            pb.ListEntitiesSensorResponse: SensorInfo,
            pb.ListEntitiesSwitchResponse: SwitchInfo,
            pb.ListEntitiesTextSensorResponse: TextSensorInfo,
            pb.ListEntitiesServicesResponse: None,
        }

        def do_append(msg):
            return isinstance(msg, tuple(response_types.keys()))

        def do_stop(msg):
            return isinstance(msg, pb.ListEntitiesDoneResponse)

        resp = await self._connection.send_message_await_response_complex(
            pb.ListEntitiesRequest(), do_append, do_stop, timeout=5)
        entities = []
        services = []
        for msg in resp:
            if isinstance(msg, pb.ListEntitiesServicesResponse):
                args = []
                for arg in msg.args:
                    args.append(UserServiceArg(
                        name=arg.name,
                        type_=arg.type,
                    ))
                services.append(UserService(
                    name=msg.name,
                    key=msg.key,
                    args=args,
                ))
                continue
            cls = None
            for resp_type, cls in response_types.items():
                if isinstance(msg, resp_type):
                    break
            kwargs = {}
            for key, _ in attr.fields_dict(cls).items():
                kwargs[key] = getattr(msg, key)
            entities.append(cls(**kwargs))
        return entities, services

    async def subscribe_states(self, on_state: Callable[[Any], None]) -> None:
        self._check_authenticated()

        response_types = {
            pb.BinarySensorStateResponse: BinarySensorState,
            pb.CoverStateResponse: CoverState,
            pb.FanStateResponse: FanState,
            pb.LightStateResponse: LightState,
            pb.SensorStateResponse: SensorState,
            pb.SwitchStateResponse: SwitchState,
            pb.TextSensorStateResponse: TextSensorState,
        }

        def on_msg(msg):
            for resp_type, cls in response_types.items():
                if isinstance(msg, resp_type):
                    break
            else:
                return

            kwargs = {}
            for key, _ in attr.fields_dict(cls).items():
                kwargs[key] = getattr(msg, key)
            on_state(cls(**kwargs))

        await self._connection.send_message_callback_response(pb.SubscribeStatesRequest(), on_msg)

    async def subscribe_logs(self, on_log: Callable[[pb.SubscribeLogsResponse], None],
                             log_level=None) -> None:
        self._check_authenticated()

        def on_msg(msg):
            if isinstance(msg, pb.SubscribeLogsResponse):
                on_log(msg)

        req = pb.SubscribeLogsRequest()
        if log_level is not None:
            req.level = log_level
        await self._connection.send_message_callback_response(req, on_msg)

    async def subscribe_service_calls(self, on_service_call: Callable[[ServiceCall], None]) -> None:
        self._check_authenticated()

        def on_msg(msg):
            if isinstance(msg, pb.ServiceCallResponse):
                kwargs = {}
                for key, _ in attr.fields_dict(ServiceCall).items():
                    kwargs[key] = getattr(msg, key)
                on_service_call(ServiceCall(**kwargs))

        await self._connection.send_message_callback_response(pb.SubscribeServiceCallsRequest(),
                                                              on_msg)

    async def subscribe_home_assistant_states(self, on_state_sub: Callable[[str], None]) -> None:
        self._check_authenticated()

        def on_msg(msg):
            if isinstance(msg, pb.SubscribeHomeAssistantStateResponse):
                on_state_sub(msg.entity_id)

        await self._connection.send_message_callback_response(
            pb.SubscribeHomeAssistantStatesRequest(), on_msg)

    async def send_home_assistant_state(self, entity_id: str, state: str) -> None:
        self._check_authenticated()

        await self._connection.send_message(pb.HomeAssistantStateResponse(
            entity_id=entity_id,
            state=state,
        ))

    async def cover_command(self,
                            key: int,
                            command: int
                            ) -> None:
        self._check_authenticated()

        req = pb.CoverCommandRequest()
        req.key = key
        req.has_state = True
        if command not in COVER_COMMANDS:
            raise ValueError
        req.command = command
        await self._connection.send_message(req)

    async def fan_command(self,
                          key: int,
                          state: Optional[bool] = None,
                          speed: Optional[int] = None,
                          oscillating: Optional[bool] = None
                          ) -> None:
        self._check_authenticated()

        req = pb.FanCommandRequest()
        req.key = key
        if state is not None:
            req.has_state = True
            req.state = state
        if speed is not None:
            req.has_speed = True
            if speed not in FAN_SPEEDS:
                raise ValueError
            req.speed = speed
        if oscillating is not None:
            req.has_oscillating = True
            req.oscillating = oscillating
        await self._connection.send_message(req)

    async def light_command(self,
                            key: int,
                            state: Optional[bool] = None,
                            brightness: Optional[float] = None,
                            rgb: Optional[Tuple[float, float, float]] = None,
                            white: Optional[float] = None,
                            color_temperature: Optional[float] = None,
                            transition_length: Optional[float] = None,
                            flash_length: Optional[float] = None,
                            effect: Optional[str] = None,
                            ):
        self._check_authenticated()

        req = pb.LightCommandRequest()
        req.key = key
        if state is not None:
            req.has_state = True
            req.state = state
        if brightness is not None:
            req.has_brightness = True
            req.brightness = brightness
        if rgb is not None:
            req.has_rgb = True
            req.red = rgb[0]
            req.green = rgb[1]
            req.blue = rgb[2]
        if white is not None:
            req.has_white = True
            req.white = white
        if color_temperature is not None:
            req.has_color_temperature = True
            req.color_temperature = color_temperature
        if transition_length is not None:
            req.has_transition_length = True
            req.transition_length = int(round(transition_length * 1000))
        if flash_length is not None:
            req.has_flash_length = True
            req.flash_length = int(round(flash_length * 1000))
        if effect is not None:
            req.has_effect = True
            req.effect = effect
        await self._connection.send_message(req)

    async def switch_command(self,
                             key: int,
                             state: bool
                             ) -> None:
        self._check_authenticated()

        req = pb.SwitchCommandRequest()
        req.key = key
        req.state = state
        await self._connection.send_message(req)

    async def execute_service(self, service: UserService, data: dict):
        self._check_authenticated()

        req = pb.ExecuteServiceRequest()
        req.key = service.key
        args = []
        for arg_desc in service.args:
            arg = pb.ExecuteServiceArgument()
            val = data[arg_desc.name]
            attr_ = {
                USER_SERVICE_ARG_BOOL: 'bool_',
                USER_SERVICE_ARG_INT: 'int_',
                USER_SERVICE_ARG_FLOAT: 'float_',
                USER_SERVICE_ARG_STRING: 'string_',
            }[arg_desc.type_]
            setattr(arg, attr_, val)
            args.append(arg)
        req.args.extend(args)
        await self._connection.send_message(req)
