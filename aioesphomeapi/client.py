import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union, cast

import attr
import zeroconf
from google.protobuf import message

from aioesphomeapi.api_pb2 import (  # type: ignore
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
    ListEntitiesRequest,
    ListEntitiesSensorResponse,
    ListEntitiesServicesResponse,
    ListEntitiesSwitchResponse,
    ListEntitiesTextSensorResponse,
    LogLevel,
    SensorStateResponse,
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
from aioesphomeapi.connection import APIConnection, ConnectionParams
from aioesphomeapi.core import APIConnectionError
from aioesphomeapi.model import (
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
    FanDirection,
    FanInfo,
    FanSpeed,
    FanState,
    HomeassistantServiceCall,
    LegacyCoverCommand,
    LightInfo,
    LightState,
    SensorInfo,
    SensorState,
    SwitchInfo,
    SwitchState,
    TextSensorInfo,
    TextSensorState,
    UserService,
    UserServiceArg,
    UserServiceArgType,
)

_LOGGER = logging.getLogger(__name__)

ExecuteServiceDataType = Dict[
    str, Union[bool, int, float, str, List[bool], List[int], List[float], List[str]]
]


class APIClient:
    def __init__(
        self,
        eventloop: asyncio.AbstractEventLoop,
        address: str,
        port: int,
        password: str,
        *,
        client_info: str = "aioesphomeapi",
        keepalive: float = 15.0,
        zeroconf_instance: Optional[zeroconf.Zeroconf] = None
    ):
        self._params = ConnectionParams(
            eventloop=eventloop,
            address=address,
            port=port,
            password=password,
            client_info=client_info,
            keepalive=keepalive,
            zeroconf_instance=zeroconf_instance,
        )
        self._connection = None  # type: Optional[APIConnection]

    async def connect(
        self,
        on_stop: Optional[Callable[[], Awaitable[None]]] = None,
        login: bool = False,
    ) -> None:
        if self._connection is not None:
            raise APIConnectionError("Already connected!")

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

    async def disconnect(self, force: bool = False) -> None:
        if self._connection is None:
            return
        await self._connection.stop(force=force)

    def _check_connected(self) -> None:
        if self._connection is None:
            raise APIConnectionError("Not connected!")
        if not self._connection.is_connected:
            raise APIConnectionError("Connection not done!")

    def _check_authenticated(self) -> None:
        self._check_connected()
        assert self._connection is not None
        if not self._connection.is_authenticated:
            raise APIConnectionError("Not authenticated!")

    async def device_info(self) -> DeviceInfo:
        self._check_connected()
        assert self._connection is not None
        resp = await self._connection.send_message_await_response(
            DeviceInfoRequest(), DeviceInfoResponse
        )
        return DeviceInfo(
            uses_password=resp.uses_password,
            name=resp.name,
            mac_address=resp.mac_address,
            esphome_version=resp.esphome_version,
            compilation_time=resp.compilation_time,
            model=resp.model,
            has_deep_sleep=resp.has_deep_sleep,
        )

    async def list_entities_services(
        self,
    ) -> Tuple[List[EntityInfo], List[UserService]]:
        self._check_authenticated()
        response_types = {
            ListEntitiesBinarySensorResponse: BinarySensorInfo,
            ListEntitiesCoverResponse: CoverInfo,
            ListEntitiesFanResponse: FanInfo,
            ListEntitiesLightResponse: LightInfo,
            ListEntitiesSensorResponse: SensorInfo,
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
                args = []
                for arg in msg.args:
                    args.append(
                        UserServiceArg(
                            name=arg.name,
                            type_=arg.type,
                        )
                    )
                services.append(
                    UserService(
                        name=msg.name,
                        key=msg.key,
                        args=args,  # type: ignore
                    )
                )
                continue
            cls = None
            for resp_type, cls in response_types.items():
                if isinstance(msg, resp_type):
                    break
            else:
                continue
            cls = cast(type, cls)
            kwargs = {}
            for key, _ in attr.fields_dict(cls).items():
                kwargs[key] = getattr(msg, key)
            entities.append(cls(**kwargs))
        return entities, services

    async def subscribe_states(self, on_state: Callable[[Any], None]) -> None:
        self._check_authenticated()

        response_types = {
            BinarySensorStateResponse: BinarySensorState,
            CoverStateResponse: CoverState,
            FanStateResponse: FanState,
            LightStateResponse: LightState,
            SensorStateResponse: SensorState,
            SwitchStateResponse: SwitchState,
            TextSensorStateResponse: TextSensorState,
            ClimateStateResponse: ClimateState,
        }

        image_stream: Dict[int, bytes] = {}

        def on_msg(msg: message.Message) -> None:
            if isinstance(msg, CameraImageResponse):
                data = image_stream.pop(msg.key, bytes()) + msg.data
                if msg.done:
                    on_state(CameraState(key=msg.key, image=data))
                else:
                    image_stream[msg.key] = data
                return

            for resp_type, cls in response_types.items():
                if isinstance(msg, resp_type):
                    break
            else:
                return

            kwargs = {}
            # pylint: disable=undefined-loop-variable
            for key, _ in attr.fields_dict(cls).items():
                kwargs[key] = getattr(msg, key)
            on_state(cls(**kwargs))

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeStatesRequest(), on_msg
        )

    async def subscribe_logs(
        self,
        on_log: Callable[[SubscribeLogsResponse], None],
        log_level: Optional[LogLevel] = None,
    ) -> None:
        self._check_authenticated()

        def on_msg(msg: message.Message) -> None:
            if isinstance(msg, SubscribeLogsResponse):
                on_log(msg)

        req = SubscribeLogsRequest()
        if log_level is not None:
            req.level = log_level
        assert self._connection is not None
        await self._connection.send_message_callback_response(req, on_msg)

    async def subscribe_service_calls(
        self, on_service_call: Callable[[HomeassistantServiceCall], None]
    ) -> None:
        self._check_authenticated()

        def on_msg(msg: message.Message) -> None:
            if isinstance(msg, HomeassistantServiceResponse):
                kwargs = {}
                for key, _ in attr.fields_dict(HomeassistantServiceCall).items():
                    kwargs[key] = getattr(msg, key)
                on_service_call(HomeassistantServiceCall(**kwargs))

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
            req.has_legacy_command = True
            if stop:
                req.legacy_command = LegacyCoverCommand.STOP
            elif position == 1.0:
                req.legacy_command = LegacyCoverCommand.OPEN
            else:
                req.legacy_command = LegacyCoverCommand.CLOSE
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
        rgb: Optional[Tuple[float, float, float]] = None,
        white: Optional[float] = None,
        color_temperature: Optional[float] = None,
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
            # pylint: disable=redefined-outer-name
            if arg_desc.type_ in map_array:
                attr = getattr(arg, map_array[arg_desc.type_])
                attr.extend(val)
            else:
                setattr(arg, map_single[arg_desc.type_], val)

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
