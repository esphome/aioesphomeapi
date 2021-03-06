import enum
from typing import List, Dict

import attr

# All fields in here should have defaults set
# Home Assistant depends on these fields being constructible
# with args from a previous version of Home Assistant.
# The default value should *always* be the Protobuf default value
# for a field (False, 0, empty string, enum with value 0, ...)


@attr.s
class APIVersion:
    major = attr.ib(type=int, default=0)
    minor = attr.ib(type=int, default=0)


@attr.s
class DeviceInfo:
    uses_password = attr.ib(type=bool, default=False)
    name = attr.ib(type=str, default='')
    mac_address = attr.ib(type=str, default='')
    compilation_time = attr.ib(type=str, default='')
    model = attr.ib(type=str, default='')
    has_deep_sleep = attr.ib(type=bool, default=False)
    esphome_version = attr.ib(type=str, default='')


@attr.s
class EntityInfo:
    object_id = attr.ib(type=str, default='')
    key = attr.ib(type=int, default=0)
    name = attr.ib(type=str, default='')
    unique_id = attr.ib(type=str, default='')


@attr.s
class EntityState:
    key = attr.ib(type=int, default=0)


# ==================== BINARY SENSOR ====================
@attr.s
class BinarySensorInfo(EntityInfo):
    device_class = attr.ib(type=str, default='')
    is_status_binary_sensor = attr.ib(type=bool, default=False)


@attr.s
class BinarySensorState(EntityState):
    state = attr.ib(type=bool, default=False)
    missing_state = attr.ib(type=bool, default=False)


# ==================== COVER ====================
@attr.s
class CoverInfo(EntityInfo):
    assumed_state = attr.ib(type=bool, default=False)
    supports_position = attr.ib(type=bool, default=False)
    supports_tilt = attr.ib(type=bool, default=False)
    device_class = attr.ib(type=str, default='')


class LegacyCoverState(enum.IntEnum):
    OPEN = 0
    CLOSED = 1


class LegacyCoverCommand(enum.IntEnum):
    OPEN = 0
    CLOSE = 1
    STOP = 2


class CoverOperation(enum.IntEnum):
    IDLE = 0
    IS_OPENING = 1
    IS_CLOSING = 2


@attr.s
class CoverState(EntityState):
    legacy_state = attr.ib(type=LegacyCoverState, converter=LegacyCoverState,
                           default=LegacyCoverState.OPEN)
    position = attr.ib(type=float, default=0.0)
    tilt = attr.ib(type=float, default=0.0)
    current_operation = attr.ib(type=CoverOperation, converter=CoverOperation,
                                default=CoverOperation.IDLE)

    def is_closed(self, api_version: APIVersion):
        if api_version >= APIVersion(1, 1):
            return self.position == 0.0
        return self.legacy_state == LegacyCoverState.CLOSED


# ==================== FAN ====================
@attr.s
class FanInfo(EntityInfo):
    supports_oscillation = attr.ib(type=bool, default=False)
    supports_speed = attr.ib(type=bool, default=False)
    supports_direction = attr.ib(type=bool, default=False)
    supported_speed_levels = attr.ib(type=int, default=3)


class FanSpeed(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class FanDirection(enum.IntEnum):
    FORWARD = 0
    REVERSE = 1


@attr.s
class FanState(EntityState):
    state = attr.ib(type=bool, default=False)
    oscillating = attr.ib(type=bool, default=False)
    speed = attr.ib(type=FanSpeed, converter=FanSpeed, default=FanSpeed.LOW)
    speed_level = attr.ib(type=int, default=0)
    direction = attr.ib(type=FanDirection, converter=FanDirection, default=FanDirection.FORWARD)


# ==================== LIGHT ====================
@attr.s
class LightInfo(EntityInfo):
    supports_brightness = attr.ib(type=bool, default=False)
    supports_rgb = attr.ib(type=bool, default=False)
    supports_white_value = attr.ib(type=bool, default=False)
    supports_color_temperature = attr.ib(type=bool, default=False)
    min_mireds = attr.ib(type=float, default=0.0)
    max_mireds = attr.ib(type=float, default=0.0)
    effects = attr.ib(type=List[str], converter=list, factory=list)


@attr.s
class LightState(EntityState):
    state = attr.ib(type=bool, default=False)
    brightness = attr.ib(type=float, default=0.0)
    red = attr.ib(type=float, default=0.0)
    green = attr.ib(type=float, default=0.0)
    blue = attr.ib(type=float, default=0.0)
    white = attr.ib(type=float, default=0.0)
    color_temperature = attr.ib(type=float, default=0.0)
    effect = attr.ib(type=str, default='')


# ==================== SENSOR ====================
@attr.s
class SensorInfo(EntityInfo):
    icon = attr.ib(type=str, default='')
    device_class = attr.ib(type=str, default='')
    unit_of_measurement = attr.ib(type=str, default='')
    accuracy_decimals = attr.ib(type=int, default=0)
    force_update = attr.ib(type=bool, default=False)


@attr.s
class SensorState(EntityState):
    state = attr.ib(type=float, default=0.0)
    missing_state = attr.ib(type=bool, default=False)


# ==================== SWITCH ====================
@attr.s
class SwitchInfo(EntityInfo):
    icon = attr.ib(type=str, default='')
    assumed_state = attr.ib(type=bool, default=False)


@attr.s
class SwitchState(EntityState):
    state = attr.ib(type=bool, default=False)


# ==================== TEXT SENSOR ====================
@attr.s
class TextSensorInfo(EntityInfo):
    icon = attr.ib(type=str, default='')


@attr.s
class TextSensorState(EntityState):
    state = attr.ib(type=str, default='')
    missing_state = attr.ib(type=bool, default=False)


# ==================== CAMERA ====================
@attr.s
class CameraInfo(EntityInfo):
    pass


@attr.s
class CameraState(EntityState):
    image = attr.ib(type=bytes, factory=bytes)


# ==================== CLIMATE ====================
class ClimateMode(enum.IntEnum):
    OFF = 0
    AUTO = 1
    COOL = 2
    HEAT = 3
    FAN_ONLY = 4
    DRY = 5


class ClimateFanMode(enum.IntEnum):
    ON = 0
    OFF = 1
    AUTO = 2
    LOW = 3
    MEDIUM = 4
    HIGH = 5
    MIDDLE = 6
    FOCUS = 7
    DIFFUSE = 8


class ClimateSwingMode(enum.IntEnum):
    OFF = 0
    BOTH = 1
    VERTICAL = 2
    HORIZONTAL = 3


class ClimateAction(enum.IntEnum):
    OFF = 0
    COOLING = 2
    HEATING = 3
    IDLE = 4
    DRYING = 5
    FAN = 6


def _convert_climate_modes(value):
    return [ClimateMode(val) for val in value]


def _convert_climate_fan_modes(value):
    return [ClimateFanMode(val) for val in value]


def _convert_climate_swing_modes(value):
    return [ClimateSwingMode(val) for val in value]


@attr.s
class ClimateInfo(EntityInfo):
    supports_current_temperature = attr.ib(type=bool, default=False)
    supports_two_point_target_temperature = attr.ib(type=bool, default=False)
    supported_modes = attr.ib(type=List[ClimateMode], converter=_convert_climate_modes,
                              factory=list)
    visual_min_temperature = attr.ib(type=float, default=0.0)
    visual_max_temperature = attr.ib(type=float, default=0.0)
    visual_temperature_step = attr.ib(type=float, default=0.0)
    supports_away = attr.ib(type=bool, default=False)
    supports_action = attr.ib(type=bool, default=False)
    supported_fan_modes = attr.ib(
        type=List[ClimateFanMode], converter=_convert_climate_fan_modes, factory=list
    )
    supported_swing_modes = attr.ib(
        type=List[ClimateSwingMode], converter=_convert_climate_swing_modes, factory=list
    )


@attr.s
class ClimateState(EntityState):
    mode = attr.ib(type=ClimateMode, converter=ClimateMode,
                   default=ClimateMode.OFF)
    action = attr.ib(type=ClimateAction, converter=ClimateAction,
                     default=ClimateAction.OFF)
    current_temperature = attr.ib(type=float, default=0.0)
    target_temperature = attr.ib(type=float, default=0.0)
    target_temperature_low = attr.ib(type=float, default=0.0)
    target_temperature_high = attr.ib(type=float, default=0.0)
    away = attr.ib(type=bool, default=False)
    fan_mode = attr.ib(
        type=ClimateFanMode, converter=ClimateFanMode, default=ClimateFanMode.AUTO
    )
    swing_mode = attr.ib(
        type=ClimateSwingMode, converter=ClimateSwingMode, default=ClimateSwingMode.OFF
    )


COMPONENT_TYPE_TO_INFO = {
    'binary_sensor': BinarySensorInfo,
    'cover': CoverInfo,
    'fan': FanInfo,
    'light': LightInfo,
    'sensor': SensorInfo,
    'switch': SwitchInfo,
    'text_sensor': TextSensorInfo,
    'camera': CameraInfo,
    'climate': ClimateInfo,
}


# ==================== USER-DEFINED SERVICES ====================
def _convert_homeassistant_service_map(value):
    return {v.key: v.value for v in value}


@attr.s
class HomeassistantServiceCall:
    service = attr.ib(type=str, default='')
    is_event = attr.ib(type=bool, default=False)
    data = attr.ib(type=Dict[str, str], converter=_convert_homeassistant_service_map,
                   factory=dict)
    data_template = attr.ib(type=Dict[str, str], converter=_convert_homeassistant_service_map,
                            factory=dict)
    variables = attr.ib(type=Dict[str, str], converter=_convert_homeassistant_service_map,
                        factory=dict)


class UserServiceArgType(enum.IntEnum):
    BOOL = 0
    INT = 1
    FLOAT = 2
    STRING = 3
    BOOL_ARRAY = 4
    INT_ARRAY = 5
    FLOAT_ARRAY = 6
    STRING_ARRAY = 7


def _attr_obj_from_dict(cls, **kwargs):
    return cls(**{key: kwargs[key] for key in attr.fields_dict(cls)})


@attr.s
class UserServiceArg:
    name = attr.ib(type=str, default='')
    type_ = attr.ib(type=UserServiceArgType, converter=UserServiceArgType,
                    default=UserServiceArgType.BOOL)


@attr.s
class UserService:
    name = attr.ib(type=str, default='')
    key = attr.ib(type=int, default=0)
    args = attr.ib(type=List[UserServiceArg], converter=list, factory=list)

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
