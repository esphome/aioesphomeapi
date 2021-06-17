import enum
from typing import Callable, List, Dict, TypeVar, Optional, Type, Any

from dataclasses import Field, dataclass, field, MISSING, fields

# All fields in here should have defaults set
# Home Assistant depends on these fields being constructible
# with args from a previous version of Home Assistant.
# The default value should *always* be the Protobuf default value
# for a field (False, 0, empty string, enum with value 0, ...)


_T = TypeVar("_T")


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


class APIDataMeta(type):
    def __new__(metacls, cls, bases, classdict):
        new_cls = super().__new__(metacls, cls, bases, classdict)
        new_cls = dataclass(frozen=True)(new_cls)
        fields_ = fields(new_cls)

        # Validate field defaults are protobuf 0 types
        for field_ in fields_:
            if field_.default is MISSING:
                continue
            if field_.default not in [False, 0, 0.0, "", b""]:
                raise ValueError(
                    f"Field {cls}.{field_.name}: default {field_.default} is invalid"
                )

        def post_init(self):
            for field_ in fields_:
                convert = field_.metadata.get("convert")
                if convert is None:
                    continue
                name = field_.name
                val = getattr(self, name)
                setattr(self, name, convert(val))

        setattr(new_cls, "__post_init__", post_init)

        return new_cls


class APIModelBase(metaclass=APIDataMeta):
    pass


def converter_field(*, converter: Callable[[Any], Any], **kwargs) -> Field:
    metadata = kwargs.pop("metadata", {})
    metadata["converter"] = converter
    return field(metadata=metadata, **kwargs)


class APIVersion(APIModelBase):
    major: int = 0
    minor: int = 0


class DeviceInfo(APIModelBase):
    uses_password: bool = False
    name: str = ""
    mac_address: str = ""
    compilation_time: str = ""
    model: str = ""
    has_deep_sleep: bool = False
    esphome_version: str = ""


class EntityInfo(APIModelBase):
    object_id: str = ""
    key: int = 0
    name: str = ""
    unique_id: str = ""


class EntityState(APIModelBase):
    key: int = 0


# ==================== BINARY SENSOR ====================
class BinarySensorInfo(EntityInfo):
    device_class: str = ""
    is_status_binary_sensor: bool = False


class BinarySensorState(EntityState):
    state: bool = False
    missing_state: bool = False


# ==================== COVER ====================
class CoverInfo(EntityInfo):
    assumed_state: bool = False
    supports_position: bool = False
    supports_tilt: bool = False
    device_class: str = ""


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


class CoverState(EntityState):
    # pylint: disable=no-member
    legacy_state: Optional[LegacyCoverState] = converter_field(
        default=LegacyCoverState.OPEN, converter=LegacyCoverState.convert
    )
    position: float = 0.0
    tilt: float = 0.0
    # pylint: disable=no-member
    current_operation: Optional[CoverOperation] = converter_field(
        default=CoverOperation.IDLE, converter=CoverOperation.convert
    )

    def is_closed(self, api_version: APIVersion):
        if api_version >= APIVersion(1, 1):
            return self.position == 0.0
        return self.legacy_state == LegacyCoverState.CLOSED


# ==================== FAN ====================
class FanInfo(EntityInfo):
    supports_oscillation: bool = False
    supports_speed: bool = False
    supports_direction: bool = False
    supported_speed_levels: int = 0


class FanSpeed(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class FanDirection(enum.IntEnum):
    FORWARD = 0
    REVERSE = 1


class FanState(EntityState):
    state: bool = False
    oscillating: bool = False
    # pylint: disable=no-member
    speed: Optional[FanSpeed] = converter_field(
        default=FanSpeed.LOW, converter=FanSpeed.convert
    )
    speed_level: int = 0
    # pylint: disable=no-member
    direction: Optional[FanDirection] = converter_field(
        default=FanDirection.FORWARD, converter=FanDirection.convert
    )


# ==================== LIGHT ====================
class LightInfo(EntityInfo):
    supports_brightness: bool = False
    supports_rgb: bool = False
    supports_white_value: bool = False
    supports_color_temperature: bool = False
    min_mireds: float = 0.0
    max_mireds: float = 0.0
    effects: List[str] = converter_field(default_factory=list, converter=list)


class LightState(EntityState):
    state: bool = False
    brightness: float = 0.0
    red: float = 0.0
    green: float = 0.0
    blue: float = 0.0
    white: float = 0.0
    color_temperature: float = 0.0
    effect: str = ""


# ==================== SENSOR ====================
class SensorStateClass(enum.IntEnum):
    NONE = 0
    MEASUREMENT = 1


class SensorInfo(EntityInfo):
    icon: str = ""
    device_class: str = ""
    unit_of_measurement: str = ""
    accuracy_decimals: int = 0
    force_update: bool = False
    # pylint: disable=no-member
    state_class: Optional[SensorStateClass] = converter_field(
        default=SensorStateClass.NONE, converter=SensorStateClass.convert
    )


class SensorState(EntityState):
    state: float = 0.0
    missing_state: bool = False


# ==================== SWITCH ====================
class SwitchInfo(EntityInfo):
    icon: str = ""
    assumed_state: bool = False


class SwitchState(EntityState):
    state: bool = False


# ==================== TEXT SENSOR ====================
class TextSensorInfo(EntityInfo):
    icon: str = ""


class TextSensorState(EntityState):
    state: str = ""
    missing_state: bool = False


# ==================== CAMERA ====================
class CameraInfo(EntityInfo):
    pass


class CameraState(EntityState):
    image: bytes = field(default_factory=bytes)


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


class ClimateInfo(EntityInfo):
    supports_current_temperature: bool = False
    supports_two_point_target_temperature: bool = False
    # pylint: disable=no-member
    supported_modes: List[ClimateMode] = converter_field(
        default_factory=list, converter=ClimateMode.convert_list
    )
    visual_min_temperature: float = 0.0
    visual_max_temperature: float = 0.0
    visual_temperature_step: float = 0.0
    supports_away: bool = False
    supports_action: bool = False
    # pylint: disable=no-member
    supported_fan_modes: List[ClimateFanMode] = converter_field(
        default_factory=list, converter=ClimateFanMode.convert_list
    )
    # pylint: disable=no-member
    supported_swing_modes: List[ClimateSwingMode] = converter_field(
        default_factory=list, converter=ClimateSwingMode.convert_list
    )


class ClimateState(EntityState):
    # pylint: disable=no-member
    mode: Optional[ClimateMode] = converter_field(
        default=ClimateMode.OFF, converter=ClimateMode.convert
    )
    # pylint: disable=no-member
    action: Optional[ClimateAction] = converter_field(
        default=ClimateAction.OFF, converter=ClimateAction.convert
    )
    current_temperature: float = 0.0
    target_temperature: float = 0.0
    target_temperature_low: float = 0.0
    target_temperature_high: float = 0.0
    away: bool = False
    # pylint: disable=no-member
    fan_mode: Optional[ClimateFanMode] = converter_field(
        default=ClimateFanMode.ON, converter=ClimateFanMode.convert
    )
    # pylint: disable=no-member
    swing_mode: Optional[ClimateSwingMode] = converter_field(
        default=ClimateSwingMode.OFF, converter=ClimateSwingMode.convert
    )


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
}


# ==================== USER-DEFINED SERVICES ====================
def _convert_homeassistant_service_map(value):
    if isinstance(value, dict):
        # already a dict, don't convert
        return value
    return {v.key: v.value for v in value}


class HomeassistantServiceCall(APIModelBase):
    service: str = ""
    is_event: bool = False
    data: Dict[str, str] = converter_field(
        default_factory=dict, converter=_convert_homeassistant_service_map
    )
    data_template: Dict[str, str] = converter_field(
        default_factory=dict, converter=_convert_homeassistant_service_map
    )
    variables: Dict[str, str] = converter_field(
        default_factory=dict, converter=_convert_homeassistant_service_map
    )


class UserServiceArgType(enum.IntEnum):
    BOOL = 0
    INT = 1
    FLOAT = 2
    STRING = 3
    BOOL_ARRAY = 4
    INT_ARRAY = 5
    FLOAT_ARRAY = 6
    STRING_ARRAY = 7


class UserServiceArg(APIModelBase):
    name: str = ""
    # pylint: disable=no-member
    type: Optional[UserServiceArgType] = converter_field(
        default=UserServiceArgType.BOOL, converter=UserServiceArgType.convert
    )

    @classmethod
    def convert_list(cls, value: List[Any]) -> List["UserServiceArg"]:
        ret = []
        for x in value:
            ret.append(UserServiceArg(x.name, x.type))
        return ret


class UserService(APIModelBase):
    name: str = ""
    key: int = 0
    # pylint: disable=no-member
    args: List[UserServiceArg] = converter_field(
        default_factory=list, converter=UserServiceArg.convert_list
    )
