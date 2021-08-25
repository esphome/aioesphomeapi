import enum
from dataclasses import asdict, dataclass, field, fields
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
    cast,
)

from .util import fix_float_single_double_conversion

if TYPE_CHECKING:
    from .api_pb2 import HomeassistantServiceMap  # type: ignore

# All fields in here should have defaults set
# Home Assistant depends on these fields being constructible
# with args from a previous version of Home Assistant.
# The default value should *always* be the Protobuf default value
# for a field (False, 0, empty string, enum with value 0, ...)

_T = TypeVar("_T", bound="APIIntEnum")
_V = TypeVar("_V")


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


@dataclass(frozen=True)
class APIModelBase:
    def __post_init__(self) -> None:
        for field_ in fields(type(self)):
            convert = field_.metadata.get("converter")
            if convert is None:
                continue
            val = getattr(self, field_.name)
            # use this setattr to prevent FrozenInstanceError
            super().__setattr__(field_.name, convert(val))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(
        cls: Type[_V], data: Dict[str, Any], *, ignore_missing: bool = True
    ) -> _V:
        init_args = {
            f.name: data[f.name]
            for f in fields(cls)
            if f.name in data or (not ignore_missing)
        }
        return cls(**init_args)  # type: ignore

    @classmethod
    def from_pb(cls: Type[_V], data: Any) -> _V:
        init_args = {f.name: getattr(data, f.name) for f in fields(cls)}
        return cls(**init_args)  # type: ignore


def converter_field(*, converter: Callable[[Any], _V], **kwargs: Any) -> _V:
    metadata = kwargs.pop("metadata", {})
    metadata["converter"] = converter
    return cast(_V, field(metadata=metadata, **kwargs))


@dataclass(frozen=True, order=True)
class APIVersion(APIModelBase):
    major: int = 0
    minor: int = 0


@dataclass(frozen=True)
class DeviceInfo(APIModelBase):
    uses_password: bool = False
    name: str = ""
    mac_address: str = ""
    compilation_time: str = ""
    model: str = ""
    has_deep_sleep: bool = False
    esphome_version: str = ""
    project_name: str = ""
    project_version: str = ""


@dataclass(frozen=True)
class EntityInfo(APIModelBase):
    object_id: str = ""
    key: int = 0
    name: str = ""
    unique_id: str = ""
    disabled_by_default: bool = False


@dataclass(frozen=True)
class EntityState(APIModelBase):
    key: int = 0


# ==================== BINARY SENSOR ====================
@dataclass(frozen=True)
class BinarySensorInfo(EntityInfo):
    device_class: str = ""
    is_status_binary_sensor: bool = False


@dataclass(frozen=True)
class BinarySensorState(EntityState):
    state: bool = False
    missing_state: bool = False


# ==================== COVER ====================
@dataclass(frozen=True)
class CoverInfo(EntityInfo):
    assumed_state: bool = False
    supports_position: bool = False
    supports_tilt: bool = False
    device_class: str = ""


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


@dataclass(frozen=True)
class CoverState(EntityState):
    legacy_state: Optional[LegacyCoverState] = converter_field(
        default=LegacyCoverState.OPEN, converter=LegacyCoverState.convert
    )
    position: float = 0.0
    tilt: float = 0.0
    current_operation: Optional[CoverOperation] = converter_field(
        default=CoverOperation.IDLE, converter=CoverOperation.convert
    )

    def is_closed(self, api_version: APIVersion) -> bool:
        if api_version < APIVersion(1, 1):
            return self.legacy_state == LegacyCoverState.CLOSED
        return self.position == 0.0


# ==================== FAN ====================
@dataclass(frozen=True)
class FanInfo(EntityInfo):
    supports_oscillation: bool = False
    supports_speed: bool = False
    supports_direction: bool = False
    supported_speed_levels: int = 0


class FanSpeed(APIIntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class FanDirection(APIIntEnum):
    FORWARD = 0
    REVERSE = 1


@dataclass(frozen=True)
class FanState(EntityState):
    state: bool = False
    oscillating: bool = False
    speed: Optional[FanSpeed] = converter_field(
        default=FanSpeed.LOW, converter=FanSpeed.convert
    )
    speed_level: int = 0
    direction: Optional[FanDirection] = converter_field(
        default=FanDirection.FORWARD, converter=FanDirection.convert
    )


# ==================== LIGHT ====================
class LightColorCapability(enum.IntFlag):
    ON_OFF = 1 << 0
    BRIGHTNESS = 1 << 1
    WHITE = 1 << 2
    COLOR_TEMPERATURE = 1 << 3
    COLD_WARM_WHITE = 1 << 4
    RGB = 1 << 5


@dataclass(frozen=True)
class LightInfo(EntityInfo):
    supported_color_modes: List[int] = converter_field(
        default_factory=list, converter=list
    )
    min_mireds: float = 0.0
    max_mireds: float = 0.0
    effects: List[str] = converter_field(default_factory=list, converter=list)

    # deprecated, do not use
    legacy_supports_brightness: bool = False
    legacy_supports_rgb: bool = False
    legacy_supports_white_value: bool = False
    legacy_supports_color_temperature: bool = False

    def supported_color_modes_compat(self, api_version: APIVersion) -> List[int]:
        if api_version < APIVersion(1, 6):
            key = (
                self.legacy_supports_brightness,
                self.legacy_supports_rgb,
                self.legacy_supports_white_value,
                self.legacy_supports_color_temperature,
            )
            # map legacy flags to color modes,
            # key: (brightness, rgb, white, color_temp)
            modes_map = {
                (False, False, False, False): [LightColorCapability.ON_OFF],
                (True, False, False, False): [
                    LightColorCapability.ON_OFF | LightColorCapability.BRIGHTNESS
                ],
                (True, False, False, True): [
                    LightColorCapability.ON_OFF
                    | LightColorCapability.BRIGHTNESS
                    | LightColorCapability.COLOR_TEMPERATURE
                ],
                (True, True, False, False): [
                    LightColorCapability.ON_OFF
                    | LightColorCapability.BRIGHTNESS
                    | LightColorCapability.RGB
                ],
                (True, True, True, False): [
                    LightColorCapability.ON_OFF
                    | LightColorCapability.BRIGHTNESS
                    | LightColorCapability.RGB
                    | LightColorCapability.WHITE
                ],
                (True, True, False, True): [
                    LightColorCapability.ON_OFF
                    | LightColorCapability.BRIGHTNESS
                    | LightColorCapability.RGB
                    | LightColorCapability.COLOR_TEMPERATURE
                ],
                (True, True, True, True): [
                    LightColorCapability.ON_OFF
                    | LightColorCapability.BRIGHTNESS
                    | LightColorCapability.RGB
                    | LightColorCapability.WHITE
                    | LightColorCapability.COLOR_TEMPERATURE
                ],
            }

            return cast(List[int], modes_map[key]) if key in modes_map else []

        return self.supported_color_modes


@dataclass(frozen=True)
class LightState(EntityState):
    state: bool = False
    brightness: float = 0.0
    color_mode: int = 0
    color_brightness: float = 0.0
    red: float = 0.0
    green: float = 0.0
    blue: float = 0.0
    white: float = 0.0
    color_temperature: float = 0.0
    cold_white: float = 0.0
    warm_white: float = 0.0
    effect: str = ""


# ==================== SENSOR ====================
class SensorStateClass(APIIntEnum):
    NONE = 0
    MEASUREMENT = 1
    TOTAL_INCREASING = 2


class LastResetType(APIIntEnum):
    NONE = 0
    NEVER = 1
    AUTO = 2


@dataclass(frozen=True)
class SensorInfo(EntityInfo):
    icon: str = ""
    device_class: str = ""
    unit_of_measurement: str = ""
    accuracy_decimals: int = 0
    force_update: bool = False
    state_class: Optional[SensorStateClass] = converter_field(
        default=SensorStateClass.NONE, converter=SensorStateClass.convert
    )
    last_reset_type: Optional[LastResetType] = converter_field(
        default=LastResetType.NONE, converter=LastResetType.convert
    )


@dataclass(frozen=True)
class SensorState(EntityState):
    state: float = 0.0
    missing_state: bool = False


# ==================== SWITCH ====================
@dataclass(frozen=True)
class SwitchInfo(EntityInfo):
    icon: str = ""
    assumed_state: bool = False


@dataclass(frozen=True)
class SwitchState(EntityState):
    state: bool = False


# ==================== TEXT SENSOR ====================
@dataclass(frozen=True)
class TextSensorInfo(EntityInfo):
    icon: str = ""


@dataclass(frozen=True)
class TextSensorState(EntityState):
    state: str = ""
    missing_state: bool = False


# ==================== CAMERA ====================
@dataclass(frozen=True)
class CameraInfo(EntityInfo):
    pass


@dataclass(frozen=True)
class CameraState(EntityState):
    data: bytes = field(default_factory=bytes)


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


@dataclass(frozen=True)
class ClimateInfo(EntityInfo):
    supports_current_temperature: bool = False
    supports_two_point_target_temperature: bool = False
    supported_modes: List[ClimateMode] = converter_field(
        default_factory=list, converter=ClimateMode.convert_list
    )
    visual_min_temperature: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    visual_max_temperature: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    visual_temperature_step: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    legacy_supports_away: bool = False
    supports_action: bool = False
    supported_fan_modes: List[ClimateFanMode] = converter_field(
        default_factory=list, converter=ClimateFanMode.convert_list
    )
    supported_swing_modes: List[ClimateSwingMode] = converter_field(
        default_factory=list, converter=ClimateSwingMode.convert_list
    )
    supported_custom_fan_modes: List[str] = converter_field(
        default_factory=list, converter=list
    )
    supported_presets: List[ClimatePreset] = converter_field(
        default_factory=list, converter=ClimatePreset.convert_list
    )
    supported_custom_presets: List[str] = converter_field(
        default_factory=list, converter=list
    )

    def supported_presets_compat(self, api_version: APIVersion) -> List[ClimatePreset]:
        if api_version < APIVersion(1, 5):
            return (
                [ClimatePreset.HOME, ClimatePreset.AWAY]
                if self.legacy_supports_away
                else []
            )
        return self.supported_presets


@dataclass(frozen=True)
class ClimateState(EntityState):
    mode: Optional[ClimateMode] = converter_field(
        default=ClimateMode.OFF, converter=ClimateMode.convert
    )
    action: Optional[ClimateAction] = converter_field(
        default=ClimateAction.OFF, converter=ClimateAction.convert
    )
    current_temperature: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    target_temperature: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    target_temperature_low: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    target_temperature_high: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    legacy_away: bool = False
    fan_mode: Optional[ClimateFanMode] = converter_field(
        default=ClimateFanMode.ON, converter=ClimateFanMode.convert
    )
    swing_mode: Optional[ClimateSwingMode] = converter_field(
        default=ClimateSwingMode.OFF, converter=ClimateSwingMode.convert
    )
    custom_fan_mode: str = ""
    preset: Optional[ClimatePreset] = converter_field(
        default=ClimatePreset.NONE, converter=ClimatePreset.convert
    )
    custom_preset: str = ""

    def preset_compat(self, api_version: APIVersion) -> Optional[ClimatePreset]:
        if api_version < APIVersion(1, 5):
            return ClimatePreset.AWAY if self.legacy_away else ClimatePreset.HOME
        return self.preset


# ==================== NUMBER ====================
@dataclass(frozen=True)
class NumberInfo(EntityInfo):
    icon: str = ""
    min_value: float = 0.0
    max_value: float = 0.0
    step: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )


@dataclass(frozen=True)
class NumberState(EntityState):
    state: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    missing_state: bool = False


# ==================== SELECT ====================
@dataclass(frozen=True)
class SelectInfo(EntityInfo):
    icon: str = ""
    options: List[str] = converter_field(default_factory=list, converter=list)


@dataclass(frozen=True)
class SelectState(EntityState):
    state: str = ""
    missing_state: bool = False


# ==================== SIREN ====================
@dataclass(frozen=True)
class SirenInfo(EntityInfo):
    icon: str = ""
    tones: List[str] = converter_field(default_factory=list, converter=list)
    supports_volume: bool = False
    supports_duration: bool = False


@dataclass(frozen=True)
class SirenState(EntityState):
    state: bool = False


COMPONENT_TYPE_TO_INFO: Dict[str, Type[EntityInfo]] = {
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
    "select": SelectInfo,
    "siren": SirenInfo,
}


# ==================== USER-DEFINED SERVICES ====================
def _convert_homeassistant_service_map(
    value: Union[Dict[str, str], Iterable["HomeassistantServiceMap"]],
) -> Dict[str, str]:
    if isinstance(value, dict):
        # already a dict, don't convert
        return value
    return {v.key: v.value for v in value}  # type: ignore


@dataclass(frozen=True)
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


class UserServiceArgType(APIIntEnum):
    BOOL = 0
    INT = 1
    FLOAT = 2
    STRING = 3
    BOOL_ARRAY = 4
    INT_ARRAY = 5
    FLOAT_ARRAY = 6
    STRING_ARRAY = 7


@dataclass(frozen=True)
class UserServiceArg(APIModelBase):
    name: str = ""
    type: Optional[UserServiceArgType] = converter_field(
        default=UserServiceArgType.BOOL, converter=UserServiceArgType.convert
    )

    @classmethod
    def convert_list(cls, value: List[Any]) -> List["UserServiceArg"]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                if "type_" in x and "type" not in x:
                    x = {**x, "type": x["type_"]}
                ret.append(UserServiceArg.from_dict(x))
            else:
                ret.append(UserServiceArg.from_pb(x))
        return ret


@dataclass(frozen=True)
class UserService(APIModelBase):
    name: str = ""
    key: int = 0
    args: List[UserServiceArg] = converter_field(
        default_factory=list, converter=UserServiceArg.convert_list
    )


class LogLevel(APIIntEnum):
    LOG_LEVEL_NONE = 0
    LOG_LEVEL_ERROR = 1
    LOG_LEVEL_WARN = 2
    LOG_LEVEL_INFO = 3
    LOG_LEVEL_CONFIG = 4
    LOG_LEVEL_DEBUG = 5
    LOG_LEVEL_VERBOSE = 6
    LOG_LEVEL_VERY_VERBOSE = 7
