import enum
from typing import List, Dict

import attr


@attr.s(cmp=True)
class APIVersion:
    major = attr.ib(type=int)
    minor = attr.ib(type=int)


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


# ==================== BINARY SENSOR ====================
@attr.s
class BinarySensorInfo(EntityInfo):
    device_class = attr.ib(type=str)
    is_status_binary_sensor = attr.ib(type=bool)


@attr.s
class BinarySensorState(EntityState):
    state = attr.ib(type=bool)


# ==================== COVER ====================
@attr.s
class CoverInfo(EntityInfo):
    assumed_state = attr.ib(type=bool)
    supports_position = attr.ib(type=bool)
    supports_tilt = attr.ib(type=bool)
    device_class = attr.ib(type=str)


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
    legacy_state = attr.ib(type=LegacyCoverState, converter=LegacyCoverState)
    position = attr.ib(type=float)
    tilt = attr.ib(type=float)
    current_operation = attr.ib(type=CoverOperation, converter=CoverOperation)

    def is_closed(self, api_version: APIVersion):
        if api_version >= APIVersion(1, 1):
            return self.position == 0.0
        return self.legacy_state == LegacyCoverState.CLOSED


# ==================== FAN ====================
@attr.s
class FanInfo(EntityInfo):
    supports_oscillation = attr.ib(type=bool)
    supports_speed = attr.ib(type=bool)


class FanSpeed(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


@attr.s
class FanState(EntityState):
    state = attr.ib(type=bool)
    oscillating = attr.ib(type=bool)
    speed = attr.ib(type=FanSpeed, converter=FanSpeed)


# ==================== LIGHT ====================
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


# ==================== SENSOR ====================
@attr.s
class SensorInfo(EntityInfo):
    icon = attr.ib(type=str)
    unit_of_measurement = attr.ib(type=str)
    accuracy_decimals = attr.ib(type=int)


@attr.s
class SensorState(EntityState):
    state = attr.ib(type=float)


# ==================== SWITCH ====================
@attr.s
class SwitchInfo(EntityInfo):
    icon = attr.ib(type=str)
    assumed_state = attr.ib(type=bool)


@attr.s
class SwitchState(EntityState):
    state = attr.ib(type=bool)


# ==================== TEXT SENSOR ====================
@attr.s
class TextSensorInfo(EntityInfo):
    icon = attr.ib(type=str)


@attr.s
class TextSensorState(EntityState):
    state = attr.ib(type=str)


# ==================== CAMERA ====================
@attr.s
class CameraInfo(EntityInfo):
    pass


@attr.s
class CameraState(EntityState):
    image = attr.ib(type=bytes)


# ==================== CLIMATE ====================
class ClimateMode(enum.IntEnum):
    OFF = 0
    AUTO = 1
    COOL = 2
    HEAT = 3


def _convert_climate_modes(value):
    return [ClimateMode(val) for val in value]


@attr.s
class ClimateInfo(EntityInfo):
    supports_current_temperature = attr.ib(type=bool)
    supports_two_point_target_temperature = attr.ib(type=bool)
    supported_modes = attr.ib(type=List[ClimateMode], converter=_convert_climate_modes)
    visual_min_temperature = attr.ib(type=float)
    visual_max_temperature = attr.ib(type=float)
    visual_temperature_step = attr.ib(type=float)
    supports_away = attr.ib(type=bool)


@attr.s
class ClimateState(EntityState):
    mode = attr.ib(type=ClimateMode, converter=ClimateMode)
    current_temperature = attr.ib(type=float)
    target_temperature = attr.ib(type=float)
    target_temperature_low = attr.ib(type=float)
    target_temperature_high = attr.ib(type=float)
    away = attr.ib(type=bool)


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
@attr.s
class ServiceCall:
    service = attr.ib(type=str)
    data = attr.ib(type=Dict[str, str], converter=dict)
    data_template = attr.ib(type=Dict[str, str], converter=dict)
    variables = attr.ib(type=Dict[str, str], converter=dict)


class UserServiceArgType(enum.IntEnum):
    BOOL = 0
    INT = 1
    FLOAT = 2
    STRING = 3


def _attr_obj_from_dict(cls, **kwargs):
    return cls(**{key: kwargs[key] for key in attr.fields_dict(cls)})


@attr.s
class UserServiceArg:
    name = attr.ib(type=str)
    type_ = attr.ib(type=UserServiceArgType, converter=UserServiceArgType)


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
