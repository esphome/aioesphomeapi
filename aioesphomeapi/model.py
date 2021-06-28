import enum
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Type, TypeVar

import attr

if TYPE_CHECKING:
    from .api_pb2 import HomeassistantServiceMap  # type: ignore

# All fields in here should have defaults set
# Home Assistant depends on these fields being constructible
# with args from a previous version of Home Assistant.
# The default value should *always* be the Protobuf default value
# for a field (False, 0, empty string, enum with value 0, ...)

_T = TypeVar("_T", bound="APIIntEnum")


class APIIntEnum(enum.IntEnum):
    """Base class for int enum values in API model."""

    @classmethod
    def convert(cls: Type[_T], value: int) -> Optional[_T]:
        try:
            return cls(value)
        except ValueError:
            return None

    @classmethod
    def convert_list(cls: Type[_T], value: List[int]) -> List[_T]:
        ret = []
        for x in value:
            try:
                ret.append(cls(x))
            except ValueError:
                pass
        return ret


@attr.s
class APIVersion:
    major = attr.ib(type=int, default=0)
    minor = attr.ib(type=int, default=0)


@attr.s
class DeviceInfo:
    uses_password = attr.ib(type=bool, default=False)
    name = attr.ib(type=str, default="")
    mac_address = attr.ib(type=str, default="")
    compilation_time = attr.ib(type=str, default="")
    model = attr.ib(type=str, default="")
    has_deep_sleep = attr.ib(type=bool, default=False)
    esphome_version = attr.ib(type=str, default="")


@attr.s
class EntityInfo:
    object_id = attr.ib(type=str, default="")
    key = attr.ib(type=int, default=0)
    name = attr.ib(type=str, default="")
    unique_id = attr.ib(type=str, default="")


@attr.s
class EntityState:
    key = attr.ib(type=int, default=0)


# ==================== BINARY SENSOR ====================
@attr.s
class BinarySensorInfo(EntityInfo):
    device_class = attr.ib(type=str, default="")
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
    device_class = attr.ib(type=str, default="")


class LegacyCoverState(APIIntEnum):
    OPEN = 0
    CLOSED = 1


class LegacyCoverCommand(APIIntEnum):
    OPEN = 0
    CLOSE = 1
    STOP = 2


class CoverOperation(APIIntEnum):
    IDLE = 0
    IS_OPENING = 1
    IS_CLOSING = 2


@attr.s
class CoverState(EntityState):
    legacy_state = attr.ib(
        type=LegacyCoverState,
        converter=LegacyCoverState.convert,  # type: ignore
        default=LegacyCoverState.OPEN,
    )
    position = attr.ib(type=float, default=0.0)
    tilt = attr.ib(type=float, default=0.0)
    current_operation = attr.ib(
        type=CoverOperation,
        converter=CoverOperation.convert,  # type: ignore
        default=CoverOperation.IDLE,
    )

    def is_closed(self, api_version: APIVersion) -> bool:
        if api_version >= APIVersion(1, 1):
            return self.position == 0.0
        return self.legacy_state == LegacyCoverState.CLOSED


# ==================== FAN ====================
@attr.s
class FanInfo(EntityInfo):
    supports_oscillation = attr.ib(type=bool, default=False)
    supports_speed = attr.ib(type=bool, default=False)
    supports_direction = attr.ib(type=bool, default=False)
    supported_speed_levels = attr.ib(type=int, default=0)


class FanSpeed(APIIntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class FanDirection(APIIntEnum):
    FORWARD = 0
    REVERSE = 1


@attr.s
class FanState(EntityState):
    state = attr.ib(type=bool, default=False)
    oscillating = attr.ib(type=bool, default=False)
    speed = attr.ib(
        type=Optional[FanSpeed],
        converter=FanSpeed.convert,  # type: ignore
        default=FanSpeed.LOW,
    )
    speed_level = attr.ib(type=int, default=0)
    direction = attr.ib(
        type=FanDirection,
        converter=FanDirection.convert,  # type: ignore
        default=FanDirection.FORWARD,
    )


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
    effect = attr.ib(type=str, default="")


# ==================== SENSOR ====================
class SensorStateClass(APIIntEnum):
    NONE = 0
    MEASUREMENT = 1


@attr.s
class SensorInfo(EntityInfo):
    icon = attr.ib(type=str, default="")
    device_class = attr.ib(type=str, default="")
    unit_of_measurement = attr.ib(type=str, default="")
    accuracy_decimals = attr.ib(type=int, default=0)
    force_update = attr.ib(type=bool, default=False)
    state_class = attr.ib(
        type=SensorStateClass,
        converter=SensorStateClass.convert,  # type: ignore
        default=SensorStateClass.NONE,
    )


@attr.s
class SensorState(EntityState):
    state = attr.ib(type=float, default=0.0)
    missing_state = attr.ib(type=bool, default=False)


# ==================== SWITCH ====================
@attr.s
class SwitchInfo(EntityInfo):
    icon = attr.ib(type=str, default="")
    assumed_state = attr.ib(type=bool, default=False)


@attr.s
class SwitchState(EntityState):
    state = attr.ib(type=bool, default=False)


# ==================== TEXT SENSOR ====================
@attr.s
class TextSensorInfo(EntityInfo):
    icon = attr.ib(type=str, default="")


@attr.s
class TextSensorState(EntityState):
    state = attr.ib(type=str, default="")
    missing_state = attr.ib(type=bool, default=False)


# ==================== CAMERA ====================
@attr.s
class CameraInfo(EntityInfo):
    pass


@attr.s
class CameraState(EntityState):
    image = attr.ib(type=bytes, factory=bytes)


# ==================== CLIMATE ====================
class ClimateMode(APIIntEnum):
    OFF = 0
    HEAT_COOL = 1
    COOL = 2
    HEAT = 3
    FAN_ONLY = 4
    DRY = 5
    AUTO = 6


class ClimateFanMode(APIIntEnum):
    ON = 0
    OFF = 1
    AUTO = 2
    LOW = 3
    MEDIUM = 4
    HIGH = 5
    MIDDLE = 6
    FOCUS = 7
    DIFFUSE = 8


class ClimateSwingMode(APIIntEnum):
    OFF = 0
    BOTH = 1
    VERTICAL = 2
    HORIZONTAL = 3


class ClimateAction(APIIntEnum):
    OFF = 0
    COOLING = 2
    HEATING = 3
    IDLE = 4
    DRYING = 5
    FAN = 6


class ClimatePreset(APIIntEnum):
    NONE = 0
    HOME = 1
    AWAY = 2
    BOOST = 3
    COMFORT = 4
    ECO = 5
    SLEEP = 6
    ACTIVITY = 7


@attr.s
class ClimateInfo(EntityInfo):
    supports_current_temperature = attr.ib(type=bool, default=False)
    supports_two_point_target_temperature = attr.ib(type=bool, default=False)
    supported_modes = attr.ib(
        type=List[ClimateMode],
        converter=ClimateMode.convert_list,  # type: ignore
        factory=list,
    )
    visual_min_temperature = attr.ib(type=float, default=0.0)
    visual_max_temperature = attr.ib(type=float, default=0.0)
    visual_temperature_step = attr.ib(type=float, default=0.0)
    legacy_supports_away = attr.ib(type=bool, default=False)
    supports_action = attr.ib(type=bool, default=False)
    supported_fan_modes = attr.ib(
        type=List[ClimateFanMode],
        converter=ClimateFanMode.convert_list,  # type: ignore
        factory=list,
    )
    supported_swing_modes = attr.ib(
        type=List[ClimateSwingMode],
        converter=ClimateSwingMode.convert_list,  # type: ignore
        factory=list,
    )
    supported_custom_fan_modes = attr.ib(type=List[str], converter=list, factory=list)
    supported_presets = attr.ib(
        type=List[ClimatePreset], converter=ClimatePreset.convert_list, factory=list  # type: ignore
    )
    supported_custom_presets = attr.ib(type=List[str], converter=list, factory=list)

    def supported_presets_compat(self, api_version: APIVersion) -> List[ClimatePreset]:
        if api_version < APIVersion(1, 5):
            return (
                [ClimatePreset.HOME, ClimatePreset.AWAY]
                if self.legacy_supports_away
                else []
            )
        return self.supported_presets


@attr.s
class ClimateState(EntityState):
    mode = attr.ib(
        type=ClimateMode,
        converter=ClimateMode.convert,  # type: ignore
        default=ClimateMode.OFF,
    )
    action = attr.ib(
        type=ClimateAction,
        converter=ClimateAction.convert,  # type: ignore
        default=ClimateAction.OFF,
    )
    current_temperature = attr.ib(type=float, default=0.0)
    target_temperature = attr.ib(type=float, default=0.0)
    target_temperature_low = attr.ib(type=float, default=0.0)
    target_temperature_high = attr.ib(type=float, default=0.0)
    legacy_away = attr.ib(type=bool, default=False)
    fan_mode = attr.ib(
        type=Optional[ClimateFanMode],
        converter=ClimateFanMode.convert,  # type: ignore
        default=ClimateFanMode.ON,
    )
    swing_mode = attr.ib(
        type=Optional[ClimateSwingMode],
        converter=ClimateSwingMode.convert,  # type: ignore
        default=ClimateSwingMode.OFF,
    )
    custom_fan_mode = attr.ib(type=str, default="")
    preset = attr.ib(
        type=Optional[ClimatePreset],
        converter=ClimatePreset.convert,  # type: ignore
        default=ClimatePreset.HOME,
    )
    custom_preset = attr.ib(type=str, default="")

    def preset_compat(self, api_version: APIVersion) -> Optional[ClimatePreset]:
        if api_version < APIVersion(1, 5):
            return ClimatePreset.AWAY if self.legacy_away else ClimatePreset.HOME
        return self.preset


# ==================== NUMBER ====================
@attr.s
class NumberInfo(EntityInfo):
    icon = attr.ib(type=str, default="")
    min_value = attr.ib(type=float, default=0.0)
    max_value = attr.ib(type=float, default=0.0)
    step = attr.ib(type=float, default=0.0)


@attr.s
class NumberState(EntityState):
    state = attr.ib(type=float, default=0.0)
    missing_state = attr.ib(type=bool, default=False)


COMPONENT_TYPE_TO_INFO = {
    "binary_sensor": BinarySensorInfo,
    "cover": CoverInfo,
    "fan": FanInfo,
    "light": LightInfo,
    "sensor": SensorInfo,
    "switch": SwitchInfo,
    "text_sensor": TextSensorInfo,
    "camera": CameraInfo,
    "climate": ClimateInfo,
    "number": NumberInfo,
}


# ==================== USER-DEFINED SERVICES ====================
def _convert_homeassistant_service_map(
    value: Iterable["HomeassistantServiceMap"],
) -> Dict[str, str]:
    return {v.key: v.value for v in value}


@attr.s
class HomeassistantServiceCall:
    service = attr.ib(type=str, default="")
    is_event = attr.ib(type=bool, default=False)
    data = attr.ib(
        type=Dict[str, str], converter=_convert_homeassistant_service_map, factory=dict
    )
    data_template = attr.ib(
        type=Dict[str, str], converter=_convert_homeassistant_service_map, factory=dict
    )
    variables = attr.ib(
        type=Dict[str, str], converter=_convert_homeassistant_service_map, factory=dict
    )


class UserServiceArgType(APIIntEnum):
    BOOL = 0
    INT = 1
    FLOAT = 2
    STRING = 3
    BOOL_ARRAY = 4
    INT_ARRAY = 5
    FLOAT_ARRAY = 6
    STRING_ARRAY = 7


_K = TypeVar("_K")


def _attr_obj_from_dict(cls: Type[_K], **kwargs: Any) -> _K:
    return cls(**{key: kwargs[key] for key in attr.fields_dict(cls)})  # type: ignore


@attr.s
class UserServiceArg:
    name = attr.ib(type=str, default="")
    type_ = attr.ib(
        type=UserServiceArgType,
        converter=UserServiceArgType.convert,  # type: ignore
        default=UserServiceArgType.BOOL,
    )


@attr.s
class UserService:
    name = attr.ib(type=str, default="")
    key = attr.ib(type=int, default=0)
    args = attr.ib(type=List[UserServiceArg], converter=list, factory=list)

    @classmethod
    def from_dict(cls, dict_: Dict[str, Any]) -> "UserService":
        args = []
        for arg in dict_.get("args", []):
            args.append(_attr_obj_from_dict(UserServiceArg, **arg))
        return cls(
            name=dict_.get("name", ""),
            key=dict_.get("key", 0),
            args=args,  # type: ignore
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "key": self.key,
            "args": [attr.asdict(arg) for arg in self.args],
        }
