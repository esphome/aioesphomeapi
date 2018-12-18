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


async def resolve_ip_address(eventloop: asyncio.events.AbstractEventLoop,
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


class APIClient:
    def __init__(self, eventloop, address: str, port: int, password: str):
        self._eventloop = eventloop  # type: asyncio.events.AbstractEventLoop
        self._address = address  # type: str
        self._port = port  # type: int
        self._password = password  # type: Optional[str]
        self._socket = None  # type: Optional[socket.socket]
        self._connected = False  # type: bool
        self._authenticated = False  # type: bool
        self._message_handlers = []  # type: List[Callable[[message], None]]
        self._keepalive = 60  # type: Union[float, int]
        self._ping_timer = None  # type: Optional[asyncio.Future]
        self.on_disconnect = None
        self.on_login = None
        self.running_event = asyncio.Event()
        self._stop_event = asyncio.Event()
        self._socket_open_event = asyncio.Event()
        self._sock_reader = None  # type: Optional[asyncio.StreamReader]
        self._sock_writer = None  # type: Optional[asyncio.StreamWriter]

        self._refresh_ping()

    def _refresh_ping(self) -> None:
        if self._ping_timer is not None:
            self._ping_timer.cancel()
            self._ping_timer = None

        async def func() -> None:
            await asyncio.sleep(self._keepalive)
            self._ping_timer = None

            if self._connected:
                try:
                    await self.ping()
                except APIConnectionError:
                    await self._on_error()

            self._refresh_ping()

        self._ping_timer = asyncio.ensure_future(func(), loop=self._eventloop)

    async def _close_socket(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        if self._sock_writer is not None:
            self._sock_writer.close()
            if hasattr(self._sock_writer, 'wait_closed'):
                await self._sock_writer.wait_closed()
            self._sock_writer = None
            self._sock_reader = None
        self._socket_open_event.clear()
        self._connected = False
        self._authenticated = False

    def _cancel_ping(self) -> None:
        if self._ping_timer is not None:
            self._ping_timer.cancel()
            self._ping_timer = None

    async def start(self) -> None:
        self._eventloop.create_task(self.run_forever())
        await self.running_event.wait()

    async def stop(self, force: bool = False) -> None:
        if not self.running_event.is_set():
            raise ValueError

        if self._connected and not force:
            try:
                await self.disconnect()
            except APIConnectionError:
                pass
        await self._close_socket()

        self._stop_event.set()
        self._cancel_ping()

    async def connect(self) -> None:
        if not self.running_event.is_set():
            raise APIConnectionError("You need to call start() first!")

        if self._connected:
            raise APIConnectionError("Already connected!")

        self._message_handlers = []

        try:
            coro = resolve_ip_address(self._eventloop, self._address, self._port)
            sockaddr = await asyncio.wait_for(coro, 15.0)
        except APIConnectionError as err:
            raise err
        except asyncio.TimeoutError:
            raise APIConnectionError("Timeout while resolving IP address")

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setblocking(False)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        _LOGGER.debug("Connecting to %s:%s (%s)", self._address, self._port, sockaddr)
        try:
            coro = self._eventloop.sock_connect(self._socket, sockaddr)
            await asyncio.wait_for(coro, 15.0)
        except OSError as err:
            await self._on_error()
            raise APIConnectionError("Error connecting to {}: {}".format(sockaddr, err))
        except asyncio.TimeoutError:
            raise APIConnectionError("Timeout while connecting to {}".format(sockaddr))

        self._sock_reader, self._sock_writer = await asyncio.open_connection(sock=self._socket)

        self._socket_open_event.set()

        hello = pb.HelloRequest()
        hello.client_info = 'Home Assistant'
        try:
            resp = await self._send_message_await_response(hello, pb.HelloResponse)
        except APIConnectionError as err:
            await self._on_error()
            raise err
        _LOGGER.debug("Successfully connected to %s ('%s' API=%s.%s)", self._address,
                      resp.server_info, resp.api_version_major, resp.api_version_minor)
        self._connected = True

    def _check_connected(self) -> None:
        if not self._connected:
            raise APIConnectionError("Must be connected!")

    async def login(self) -> None:
        self._check_connected()
        if self._authenticated:
            raise APIConnectionError("Already logged in!")

        connect = pb.ConnectRequest()
        if self._password is not None:
            connect.password = self._password
        resp = await self._send_message_await_response(connect, pb.ConnectResponse)
        if resp.invalid_password:
            raise APIConnectionError("Invalid password!")

        self._authenticated = True
        if self.on_login is not None:
            await self.on_login()

    async def _on_error(self) -> None:
        was_connected = self._connected

        await self._close_socket()

        if was_connected and self.on_disconnect is not None:
            await self.on_disconnect()

    async def _write(self, data: bytes) -> None:
        _LOGGER.debug("Write: %s", ' '.join('{:02X}'.format(x) for x in data))
        try:
            self._sock_writer.write(data)
            await self._sock_writer.drain()
        except OSError as err:
            await self._on_error()
            raise APIConnectionError("Error while writing data: {}".format(err))

    async def _send_message(self, msg: message.Message) -> None:
        for message_type, klass in MESSAGE_TYPE_TO_PROTO.items():
            if isinstance(msg, klass):
                break
        else:
            raise ValueError

        encoded = msg.SerializeToString()
        _LOGGER.debug("Sending %s: %s", type(msg), str(msg))
        req = bytes([0])
        req += _varuint_to_bytes(len(encoded))
        req += _varuint_to_bytes(message_type)
        req += encoded
        await self._write(req)
        self._refresh_ping()

    async def _send_message_await_response_complex(self, send_msg: message.Message,
                                                   do_append: Callable[[Any], bool],
                                                   do_stop: Callable[[Any], bool],
                                                   timeout: float = 1.0) -> List[Any]:
        fut = self._eventloop.create_future()
        responses = []

        def on_message(resp):
            if do_append(resp):
                responses.append(resp)
            if do_stop(resp):
                fut.set_result(responses)

        self._message_handlers.append(on_message)
        await self._send_message(send_msg)

        try:
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            raise APIConnectionError("Timeout while waiting for API response!")

        try:
            self._message_handlers.remove(on_message)
        except ValueError:
            pass

        return responses

    async def _send_message_await_response(self,
                                           send_msg: message.Message,
                                           response_type: Any, timeout: float = 1.0) -> Any:
        def is_response(msg):
            return isinstance(msg, response_type)

        res = await self._send_message_await_response_complex(
            send_msg, is_response, is_response, timeout=timeout)
        if len(res) != 1:
            raise APIConnectionError("Expected one result, got {}".format(len(res)))

        return res[0]

    async def device_info(self) -> DeviceInfo:
        self._check_connected()
        resp = await self._send_message_await_response(
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

    async def ping(self) -> None:
        self._check_connected()
        await self._send_message_await_response(pb.PingRequest(), pb.PingResponse)
        return

    async def disconnect(self) -> None:
        self._check_connected()

        try:
            await self._send_message_await_response(pb.DisconnectRequest(), pb.DisconnectResponse)
        except APIConnectionError:
            pass
        await self._close_socket()

        if self.on_disconnect is not None:
            await self.on_disconnect()

    def _check_authenticated(self) -> None:
        if not self._authenticated:
            raise APIConnectionError("Must login first!")

    async def list_entities(self) -> List[Any]:
        self._check_authenticated()
        response_types = {
            pb.ListEntitiesBinarySensorResponse: BinarySensorInfo,
            pb.ListEntitiesCoverResponse: CoverInfo,
            pb.ListEntitiesFanResponse: FanInfo,
            pb.ListEntitiesLightResponse: LightInfo,
            pb.ListEntitiesSensorResponse: SensorInfo,
            pb.ListEntitiesSwitchResponse: SwitchInfo,
            pb.ListEntitiesTextSensorResponse: TextSensorInfo,
        }

        def do_append(msg):
            return isinstance(msg, tuple(response_types.keys()))

        def do_stop(msg):
            return isinstance(msg, pb.ListEntitiesDoneResponse)

        resp = await self._send_message_await_response_complex(
            pb.ListEntitiesRequest(), do_append, do_stop, timeout=5)
        entities = []
        for msg in resp:
            cls = None
            for resp_type, cls in response_types.items():
                if isinstance(msg, resp_type):
                    break
            kwargs = {}
            for key, _ in attr.fields_dict(cls).items():
                kwargs[key] = getattr(msg, key)
            entities.append(cls(**kwargs))
        return entities

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

        self._message_handlers.append(on_msg)
        await self._send_message(pb.SubscribeStatesRequest())

    async def subscribe_logs(self, on_log: Callable[[pb.SubscribeLogsResponse], None],
                             log_level=None) -> None:
        self._check_authenticated()

        def on_msg(msg):
            if isinstance(msg, pb.SubscribeLogsResponse):
                on_log(msg)

        self._message_handlers.append(on_msg)
        req = pb.SubscribeLogsRequest()
        if log_level is not None:
            req.level = log_level
        await self._send_message(req)

    async def subscribe_service_calls(self, on_service_call: Callable[[ServiceCall], None]) -> None:
        self._check_authenticated()

        def on_msg(msg):
            if isinstance(msg, pb.ServiceCallResponse):
                kwargs = {}
                for key, _ in attr.fields_dict(ServiceCall).items():
                    kwargs[key] = getattr(msg, key)
                on_service_call(ServiceCall(**kwargs))

        self._message_handlers.append(on_msg)
        await self._send_message(pb.SubscribeServiceCallsRequest())

    async def subscribe_home_assistant_states(self, on_state_sub: Callable[[str], None]) -> None:
        self._check_authenticated()

        def on_msg(msg):
            if isinstance(msg, pb.SubscribeHomeAssistantStateResponse):
                on_state_sub(msg.entity_id)

        self._message_handlers.append(on_msg)
        await self._send_message(pb.SubscribeHomeAssistantStatesRequest())

    async def send_home_assistant_state(self, entity_id: str, state: str) -> None:
        self._check_authenticated()

        await self._send_message(pb.HomeAssistantStateResponse(
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
        await self._send_message(req)

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
        await self._send_message(req)

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
            req.transition_length = int(round(transition_length / 1000))
        if flash_length is not None:
            req.has_flash_length = True
            req.flash_length = int(round(flash_length / 1000))
        if effect is not None:
            req.has_effect = True
            req.effect = effect
        await self._send_message(req)

    async def switch_command(self,
                             key: int,
                             state: bool
                             ) -> None:
        self._check_authenticated()

        req = pb.SwitchCommandRequest()
        req.key = key
        req.state = state
        await self._send_message(req)

    async def _recv(self, amount: int) -> bytes:
        if amount == 0:
            return bytes()

        try:
            ret = await self._sock_reader.readexactly(amount)
        except (asyncio.IncompleteReadError, OSError) as err:
            raise APIConnectionError("Error while receiving data: {}".format(err))

        return ret

    async def _recv_varint(self) -> int:
        raw = bytes()
        while not raw or raw[-1] & 0x80:
            raw += await self._recv(1)
        return cast(int, _bytes_to_varuint(raw))

    async def _run_once(self) -> None:
        await self._socket_open_event.wait()

        preamble = await self._recv(1)
        if preamble[0] != 0x00:
            raise APIConnectionError("Invalid preamble")

        length = await self._recv_varint()
        msg_type = await self._recv_varint()

        raw_msg = await self._recv(length)
        if msg_type not in MESSAGE_TYPE_TO_PROTO:
            _LOGGER.debug("Skipping message type %s", msg_type)
            return

        msg = MESSAGE_TYPE_TO_PROTO[msg_type]()
        msg.ParseFromString(raw_msg)
        _LOGGER.debug("Got message of type %s: %s", type(msg), msg)
        for msg_handler in self._message_handlers[:]:
            msg_handler(msg)
        await self._handle_internal_messages(msg)
        self._refresh_ping()

    async def run_forever(self) -> None:
        if self.running_event.is_set():
            raise ValueError
        self.running_event.set()
        try:
            while True:
                try:
                    await self._run_once()
                except APIConnectionError as err:
                    if self._connected:
                        _LOGGER.debug("Error while reading incoming messages: %s", err)
                        await self._on_error()
        except asyncio.CancelledError:
            self.running_event.clear()
            raise

    async def _handle_internal_messages(self, msg: Any) -> None:
        if isinstance(msg, pb.DisconnectRequest):
            await self._send_message(pb.DisconnectResponse())
            await self._close_socket()
            if self.on_disconnect is not None:
                await self.on_disconnect()
        elif isinstance(msg, pb.PingRequest):
            await self._send_message(pb.PingResponse())
        elif isinstance(msg, pb.GetTimeRequest):
            resp = pb.GetTimeResponse()
            resp.epoch_seconds = int(time.time())
            await self._send_message(resp)
