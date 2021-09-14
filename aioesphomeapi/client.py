import asyncio
import logging
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
)

from google.protobuf import message

from .api_pb2 import (  # type: ignore
    BinarySensorStateResponse,
    CameraImageRequest,
    CameraImageResponse,
    ClimateCommandRequest,
    ClimateStateResponse,
    CoverCommandRequest,
    CoverStateResponse,
    DeviceInfoRequest,
    DeviceInfoResponse,
    ExecuteServiceArgument,
    ExecuteServiceRequest,
    FanCommandRequest,
    FanStateResponse,
    HomeassistantServiceResponse,
    HomeAssistantStateResponse,
    LightCommandRequest,
    LightStateResponse,
    ListEntitiesBinarySensorResponse,
    ListEntitiesCameraResponse,
    ListEntitiesClimateResponse,
    ListEntitiesCoverResponse,
    ListEntitiesDoneResponse,
    ListEntitiesFanResponse,
    ListEntitiesLightResponse,
    ListEntitiesNumberResponse,
    ListEntitiesRequest,
    ListEntitiesSelectResponse,
    ListEntitiesSensorResponse,
    ListEntitiesServicesResponse,
    ListEntitiesSirenResponse,
    ListEntitiesSwitchResponse,
    ListEntitiesTextSensorResponse,
    NumberCommandRequest,
    NumberStateResponse,
    SelectCommandRequest,
    SelectStateResponse,
    SensorStateResponse,
    SirenCommandRequest,
    SirenStateResponse,
    SubscribeHomeassistantServicesRequest,
    SubscribeHomeAssistantStateResponse,
    SubscribeHomeAssistantStatesRequest,
    SubscribeLogsRequest,
    SubscribeLogsResponse,
    SubscribeStatesRequest,
    SwitchCommandRequest,
    SwitchStateResponse,
    TextSensorStateResponse,
)
from .connection import APIConnection, ConnectionParams
from .core import APIConnectionError
from .host_resolver import ZeroconfInstanceType
from .model import (
    APIVersion,
    BinarySensorInfo,
    BinarySensorState,
    CameraInfo,
    CameraState,
    ClimateFanMode,
    ClimateInfo,
    ClimateMode,
    ClimatePreset,
    ClimateState,
    ClimateSwingMode,
    CoverInfo,
    CoverState,
    DeviceInfo,
    EntityInfo,
    EntityState,
    FanDirection,
    FanInfo,
    FanSpeed,
    FanState,
    HomeassistantServiceCall,
    LegacyCoverCommand,
    LightInfo,
    LightState,
    LogLevel,
    NumberInfo,
    NumberState,
    SelectInfo,
    SelectState,
    SensorInfo,
    SensorState,
    SirenInfo,
    SirenState,
    SwitchInfo,
    SwitchState,
    TextSensorInfo,
    TextSensorState,
    UserService,
    UserServiceArgType,
)

_LOGGER = logging.getLogger(__name__)

ExecuteServiceDataType = Dict[
    str, Union[bool, int, float, str, List[bool], List[int], List[float], List[str]]
]


# pylint: disable=too-many-public-methods
class APIClient:
    def __init__(
        self,
        eventloop: asyncio.AbstractEventLoop,
        address: str,
        port: int,
        password: Optional[str],
        *,
        client_info: str = "aioesphomeapi",
        keepalive: float = 15.0,
        zeroconf_instance: ZeroconfInstanceType = None,
        noise_psk: Optional[str] = None,
    ):
        self._params = ConnectionParams(
            eventloop=eventloop,
            address=address,
            port=port,
            password=password,
            client_info=client_info,
            keepalive=keepalive,
            zeroconf_instance=zeroconf_instance,
            # treat empty psk string as missing (like password)
            noise_psk=noise_psk or None,
        )
        self._connection: Optional[APIConnection] = None
        self._cached_name: Optional[str] = None

    @property
    def address(self) -> str:
        return self._params.address

    @property
    def _log_name(self) -> str:
        if self._cached_name is not None:
            return f"{self._cached_name} @ {self.address}"
        return self.address

    async def connect(
        self,
        on_stop: Optional[Callable[[], Awaitable[None]]] = None,
        login: bool = False,
    ) -> None:
        if self._connection is not None:
            raise APIConnectionError(f"Already connected to {self._log_name}!")

        connected = False
        stopped = False

        async def _on_stop() -> None:
            nonlocal stopped

            if stopped:
                return
            stopped = True
            self._connection = None
            if connected and on_stop is not None:
                await on_stop()

        self._connection = APIConnection(self._params, _on_stop)
        self._connection.log_name = self._log_name

        try:
            await self._connection.connect()
            if login:
                await self._connection.login()
        except APIConnectionError:
            await _on_stop()
            raise
        except Exception as e:
            await _on_stop()
            raise APIConnectionError(
                f"Unexpected error while connecting to {self._log_name}: {e}"
            ) from e

        connected = True

    async def disconnect(self, force: bool = False) -> None:
        if self._connection is None:
            return
        await self._connection.stop(force=force)

    def _check_connected(self) -> None:
        if self._connection is None:
            raise APIConnectionError(f"Not connected to {self._log_name}!")
        if not self._connection.is_connected:
            raise APIConnectionError(f"Connection not done for {self._log_name}!")

    def _check_authenticated(self) -> None:
        self._check_connected()
        assert self._connection is not None
        if not self._connection.is_authenticated:
            raise APIConnectionError(f"Not authenticated for {self._log_name}!")

    async def device_info(self) -> DeviceInfo:
        self._check_connected()
        assert self._connection is not None
        resp = await self._connection.send_message_await_response(
            DeviceInfoRequest(), DeviceInfoResponse
        )
        info = DeviceInfo.from_pb(resp)
        self._cached_name = info.name
        self._connection.log_name = self._log_name
        return info

    async def list_entities_services(
        self,
    ) -> Tuple[List[EntityInfo], List[UserService]]:
        self._check_authenticated()
        response_types: Dict[Any, Optional[Type[EntityInfo]]] = {
            ListEntitiesBinarySensorResponse: BinarySensorInfo,
            ListEntitiesCoverResponse: CoverInfo,
            ListEntitiesFanResponse: FanInfo,
            ListEntitiesLightResponse: LightInfo,
            ListEntitiesNumberResponse: NumberInfo,
            ListEntitiesSelectResponse: SelectInfo,
            ListEntitiesSensorResponse: SensorInfo,
            ListEntitiesSirenResponse: SirenInfo,
            ListEntitiesSwitchResponse: SwitchInfo,
            ListEntitiesTextSensorResponse: TextSensorInfo,
            ListEntitiesServicesResponse: None,
            ListEntitiesCameraResponse: CameraInfo,
            ListEntitiesClimateResponse: ClimateInfo,
        }

        def do_append(msg: message.Message) -> bool:
            return isinstance(msg, tuple(response_types.keys()))

        def do_stop(msg: message.Message) -> bool:
            return isinstance(msg, ListEntitiesDoneResponse)

        assert self._connection is not None
        resp = await self._connection.send_message_await_response_complex(
            ListEntitiesRequest(), do_append, do_stop, timeout=5
        )
        entities: List[EntityInfo] = []
        services: List[UserService] = []
        for msg in resp:
            if isinstance(msg, ListEntitiesServicesResponse):
                services.append(UserService.from_pb(msg))
                continue
            cls = None
            for resp_type, cls in response_types.items():
                if isinstance(msg, resp_type):
                    break
            else:
                continue
            assert cls is not None
            entities.append(cls.from_pb(msg))
        return entities, services

    async def subscribe_states(self, on_state: Callable[[EntityState], None]) -> None:
        self._check_authenticated()

        response_types: Dict[Any, Type[EntityState]] = {
            BinarySensorStateResponse: BinarySensorState,
            CoverStateResponse: CoverState,
            FanStateResponse: FanState,
            LightStateResponse: LightState,
            NumberStateResponse: NumberState,
            SelectStateResponse: SelectState,
            SensorStateResponse: SensorState,
            SirenStateResponse: SirenState,
            SwitchStateResponse: SwitchState,
            TextSensorStateResponse: TextSensorState,
            ClimateStateResponse: ClimateState,
        }

        image_stream: Dict[int, bytes] = {}

        def on_msg(msg: message.Message) -> None:
            if isinstance(msg, CameraImageResponse):
                data = image_stream.pop(msg.key, bytes()) + msg.data
                if msg.done:
                    # Return CameraState with the merged data
                    on_state(CameraState(key=msg.key, data=data))
                else:
                    image_stream[msg.key] = data
                return

            for resp_type, cls in response_types.items():
                if isinstance(msg, resp_type):
                    break
            else:
                return

            # pylint: disable=undefined-loop-variable
            on_state(cls.from_pb(msg))

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeStatesRequest(), on_msg
        )

    async def subscribe_logs(
        self,
        on_log: Callable[[SubscribeLogsResponse], None],
        log_level: Optional[LogLevel] = None,
        dump_config: Optional[bool] = None,
    ) -> None:
        self._check_authenticated()

        def on_msg(msg: message.Message) -> None:
            if isinstance(msg, SubscribeLogsResponse):
                on_log(msg)

        req = SubscribeLogsRequest()
        if log_level is not None:
            req.level = log_level
        if dump_config is not None:
            req.dump_config = dump_config
        assert self._connection is not None
        await self._connection.send_message_callback_response(req, on_msg)

    async def subscribe_service_calls(
        self, on_service_call: Callable[[HomeassistantServiceCall], None]
    ) -> None:
        self._check_authenticated()

        def on_msg(msg: message.Message) -> None:
            if isinstance(msg, HomeassistantServiceResponse):
                on_service_call(HomeassistantServiceCall.from_pb(msg))

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeHomeassistantServicesRequest(), on_msg
        )

    async def subscribe_home_assistant_states(
        self, on_state_sub: Callable[[str, Optional[str]], None]
    ) -> None:
        self._check_authenticated()

        def on_msg(msg: message.Message) -> None:
            if isinstance(msg, SubscribeHomeAssistantStateResponse):
                on_state_sub(msg.entity_id, msg.attribute)

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeHomeAssistantStatesRequest(), on_msg
        )

    async def send_home_assistant_state(
        self, entity_id: str, attribute: Optional[str], state: str
    ) -> None:
        self._check_authenticated()

        assert self._connection is not None
        await self._connection.send_message(
            HomeAssistantStateResponse(
                entity_id=entity_id,
                state=state,
                attribute=attribute,
            )
        )

    async def cover_command(
        self,
        key: int,
        position: Optional[float] = None,
        tilt: Optional[float] = None,
        stop: bool = False,
    ) -> None:
        self._check_authenticated()

        req = CoverCommandRequest()
        req.key = key
        apiv = cast(APIVersion, self.api_version)
        if apiv >= APIVersion(1, 1):
            if position is not None:
                req.has_position = True
                req.position = position
            if tilt is not None:
                req.has_tilt = True
                req.tilt = tilt
            if stop:
                req.stop = stop
        else:
            if stop:
                req.legacy_command = LegacyCoverCommand.STOP
                req.has_legacy_command = True
            elif position == 1.0:
                req.legacy_command = LegacyCoverCommand.OPEN
                req.has_legacy_command = True
            elif position == 0.0:
                req.legacy_command = LegacyCoverCommand.CLOSE
                req.has_legacy_command = True
        assert self._connection is not None
        await self._connection.send_message(req)

    async def fan_command(
        self,
        key: int,
        state: Optional[bool] = None,
        speed: Optional[FanSpeed] = None,
        speed_level: Optional[int] = None,
        oscillating: Optional[bool] = None,
        direction: Optional[FanDirection] = None,
    ) -> None:
        self._check_authenticated()

        req = FanCommandRequest()
        req.key = key
        if state is not None:
            req.has_state = True
            req.state = state
        if speed is not None:
            req.has_speed = True
            req.speed = speed
        if speed_level is not None:
            req.has_speed_level = True
            req.speed_level = speed_level
        if oscillating is not None:
            req.has_oscillating = True
            req.oscillating = oscillating
        if direction is not None:
            req.has_direction = True
            req.direction = direction
        assert self._connection is not None
        await self._connection.send_message(req)

    async def light_command(
        self,
        key: int,
        state: Optional[bool] = None,
        brightness: Optional[float] = None,
        color_mode: Optional[int] = None,
        color_brightness: Optional[float] = None,
        rgb: Optional[Tuple[float, float, float]] = None,
        white: Optional[float] = None,
        color_temperature: Optional[float] = None,
        cold_white: Optional[float] = None,
        warm_white: Optional[float] = None,
        transition_length: Optional[float] = None,
        flash_length: Optional[float] = None,
        effect: Optional[str] = None,
    ) -> None:
        self._check_authenticated()

        req = LightCommandRequest()
        req.key = key
        if state is not None:
            req.has_state = True
            req.state = state
        if brightness is not None:
            req.has_brightness = True
            req.brightness = brightness
        if color_mode is not None:
            req.has_color_mode = True
            req.color_mode = color_mode
        if color_brightness is not None:
            req.has_color_brightness = True
            req.color_brightness = color_brightness
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
        if cold_white is not None:
            req.has_cold_white = True
            req.cold_white = cold_white
        if warm_white is not None:
            req.has_warm_white = True
            req.warm_white = warm_white
        if transition_length is not None:
            req.has_transition_length = True
            req.transition_length = int(round(transition_length * 1000))
        if flash_length is not None:
            req.has_flash_length = True
            req.flash_length = int(round(flash_length * 1000))
        if effect is not None:
            req.has_effect = True
            req.effect = effect
        assert self._connection is not None
        await self._connection.send_message(req)

    async def switch_command(self, key: int, state: bool) -> None:
        self._check_authenticated()

        req = SwitchCommandRequest()
        req.key = key
        req.state = state
        assert self._connection is not None
        await self._connection.send_message(req)

    async def climate_command(
        self,
        key: int,
        mode: Optional[ClimateMode] = None,
        target_temperature: Optional[float] = None,
        target_temperature_low: Optional[float] = None,
        target_temperature_high: Optional[float] = None,
        fan_mode: Optional[ClimateFanMode] = None,
        swing_mode: Optional[ClimateSwingMode] = None,
        custom_fan_mode: Optional[str] = None,
        preset: Optional[ClimatePreset] = None,
        custom_preset: Optional[str] = None,
    ) -> None:
        self._check_authenticated()

        req = ClimateCommandRequest()
        req.key = key
        if mode is not None:
            req.has_mode = True
            req.mode = mode
        if target_temperature is not None:
            req.has_target_temperature = True
            req.target_temperature = target_temperature
        if target_temperature_low is not None:
            req.has_target_temperature_low = True
            req.target_temperature_low = target_temperature_low
        if target_temperature_high is not None:
            req.has_target_temperature_high = True
            req.target_temperature_high = target_temperature_high
        if fan_mode is not None:
            req.has_fan_mode = True
            req.fan_mode = fan_mode
        if swing_mode is not None:
            req.has_swing_mode = True
            req.swing_mode = swing_mode
        if custom_fan_mode is not None:
            req.has_custom_fan_mode = True
            req.custom_fan_mode = custom_fan_mode
        if preset is not None:
            apiv = cast(APIVersion, self.api_version)
            if apiv < APIVersion(1, 5):
                req.has_legacy_away = True
                req.legacy_away = preset == ClimatePreset.AWAY
            else:
                req.has_preset = True
                req.preset = preset
        if custom_preset is not None:
            req.has_custom_preset = True
            req.custom_preset = custom_preset
        assert self._connection is not None
        await self._connection.send_message(req)

    async def number_command(self, key: int, state: float) -> None:
        self._check_authenticated()

        req = NumberCommandRequest()
        req.key = key
        req.state = state
        assert self._connection is not None
        await self._connection.send_message(req)

    async def select_command(self, key: int, state: str) -> None:
        self._check_authenticated()

        req = SelectCommandRequest()
        req.key = key
        req.state = state
        assert self._connection is not None
        await self._connection.send_message(req)

    async def siren_command(
        self,
        key: int,
        state: Optional[bool] = None,
        tone: Optional[str] = None,
        volume: Optional[float] = None,
        duration: Optional[int] = None,
    ) -> None:
        self._check_authenticated()

        req = SirenCommandRequest()
        req.key = key
        if state is not None:
            req.state = state
            req.has_state = True
        if tone is not None:
            req.tone = tone
            req.has_tone = True
        if volume is not None:
            req.volume = volume
            req.has_volume = True
        if duration is not None:
            req.duration = duration
            req.has_duration = True
        assert self._connection is not None
        await self._connection.send_message(req)

    async def execute_service(
        self, service: UserService, data: ExecuteServiceDataType
    ) -> None:
        self._check_authenticated()

        req = ExecuteServiceRequest()
        req.key = service.key
        args = []
        for arg_desc in service.args:
            arg = ExecuteServiceArgument()
            val = data[arg_desc.name]
            apiv = cast(APIVersion, self.api_version)
            int_type = "int_" if apiv >= APIVersion(1, 3) else "legacy_int"
            map_single = {
                UserServiceArgType.BOOL: "bool_",
                UserServiceArgType.INT: int_type,
                UserServiceArgType.FLOAT: "float_",
                UserServiceArgType.STRING: "string_",
            }
            map_array = {
                UserServiceArgType.BOOL_ARRAY: "bool_array",
                UserServiceArgType.INT_ARRAY: "int_array",
                UserServiceArgType.FLOAT_ARRAY: "float_array",
                UserServiceArgType.STRING_ARRAY: "string_array",
            }
            if arg_desc.type in map_array:
                attr = getattr(arg, map_array[arg_desc.type])
                attr.extend(val)
            else:
                assert arg_desc.type in map_single
                setattr(arg, map_single[arg_desc.type], val)

            args.append(arg)
        # pylint: disable=no-member
        req.args.extend(args)
        assert self._connection is not None
        await self._connection.send_message(req)

    async def _request_image(
        self, *, single: bool = False, stream: bool = False
    ) -> None:
        req = CameraImageRequest()
        req.single = single
        req.stream = stream
        assert self._connection is not None
        await self._connection.send_message(req)

    async def request_single_image(self) -> None:
        await self._request_image(single=True)

    async def request_image_stream(self) -> None:
        await self._request_image(stream=True)

    @property
    def api_version(self) -> Optional[APIVersion]:
        if self._connection is None:
            return None
        return self._connection.api_version
