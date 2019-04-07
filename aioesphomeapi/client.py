import logging
from typing import Any, Callable, Optional, Tuple

import aioesphomeapi.api_pb2 as pb
from aioesphomeapi.connection import APIConnection, ConnectionParams
from aioesphomeapi.core import APIConnectionError
from aioesphomeapi.model import *

_LOGGER = logging.getLogger(__name__)


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
            pb.ListEntitiesCameraResponse: CameraInfo,
            pb.ListEntitiesClimateResponse: ClimateInfo,
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
            pb.ClimateStateResponse: ClimateState,
        }

        image_stream = {}

        def on_msg(msg):
            if isinstance(msg, pb.CameraImageResponse):
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
                            position: Optional[float] = None,
                            tilt: Optional[float] = None,
                            stop: bool = False,
                            ) -> None:
        self._check_authenticated()

        req = pb.CoverCommandRequest()
        req.key = key
        if self.api_version >= APIVersion(1, 1):
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
        await self._connection.send_message(req)

    async def fan_command(self,
                          key: int,
                          state: Optional[bool] = None,
                          speed: Optional[FanSpeed] = None,
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

    async def climate_command(self,
                              key: int,
                              mode: Optional[ClimateMode] = None,
                              target_temperature: Optional[float] = None,
                              target_temperature_low: Optional[float] = None,
                              target_temperature_high: Optional[float] = None,
                              away: Optional[bool] = None,
                              ) -> None:
        self._check_authenticated()

        req = pb.ClimateCommandRequest()
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
        if away is not None:
            req.has_away = True
            req.away = away
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
                UserServiceArgType.BOOL: 'bool_',
                UserServiceArgType.INT: 'int_',
                UserServiceArgType.FLOAT: 'float_',
                UserServiceArgType.STRING: 'string_',
            }[arg_desc.type_]
            setattr(arg, attr_, val)
            args.append(arg)
        req.args.extend(args)
        await self._connection.send_message(req)

    async def _request_image(self, *, single=False, stream=False):
        req = pb.CameraImageRequest()
        req.single = single
        req.stream = stream
        await self._connection.send_message(req)

    async def request_single_image(self):
        await self._request_image(single=True)

    async def request_image_stream(self):
        await self._request_image(stream=True)

    @property
    def api_version(self) -> Optional[APIVersion]:
        if self._connection is None:
            return None
        return self._connection.api_version
