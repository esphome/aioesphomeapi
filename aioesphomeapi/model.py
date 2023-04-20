import enum
import sys
from dataclasses import asdict, dataclass, field, fields
from functools import cache, lru_cache
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
    cast,
)
from uuid import UUID

from .util import fix_float_single_double_conversion

if sys.version_info[:2] < (3, 10):
    _dataclass_decorator = dataclass()
else:
    _dataclass_decorator = dataclass(  # pylint: disable=unexpected-keyword-arg
        slots=True
    )

if TYPE_CHECKING:
    from .api_pb2 import (  # type: ignore
        BluetoothLEAdvertisementResponse,
        BluetoothServiceData,
        HomeassistantServiceMap,
    )

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


# Fields do not change so we can cache the result
# of calling fields() on the dataclass
cached_fields = cache(fields)


@dataclass(frozen=True)
class APIModelBase:
    def __post_init__(self) -> None:
        for field_ in cached_fields(type(self)):  # type: ignore[arg-type]
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
            for f in cached_fields(cls)  # type: ignore[arg-type]
            if f.name in data or (not ignore_missing)
        }
        return cls(**init_args)

    @classmethod
    def from_pb(cls: Type[_V], data: Any) -> _V:
        return cls(**{f.name: getattr(data, f.name) for f in cached_fields(cls)})  # type: ignore[arg-type]


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
    friendly_name: str = ""
    mac_address: str = ""
    compilation_time: str = ""
    model: str = ""
    manufacturer: str = ""
    has_deep_sleep: bool = False
    esphome_version: str = ""
    project_name: str = ""
    project_version: str = ""
    webserver_port: int = 0
    bluetooth_proxy_version: int = 0
    voice_assistant_version: int = 0


class EntityCategory(APIIntEnum):
    NONE = 0
    CONFIG = 1
    DIAGNOSTIC = 2


@dataclass(frozen=True)
class EntityInfo(APIModelBase):
    object_id: str = ""
    key: int = 0
    name: str = ""
    unique_id: str = ""
    disabled_by_default: bool = False
    icon: str = ""
    entity_category: Optional[EntityCategory] = converter_field(
        default=EntityCategory.NONE, converter=EntityCategory.convert
    )


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
    supports_stop: bool = False
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
    position: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    tilt: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
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
    min_mireds: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    max_mireds: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
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
    brightness: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    color_mode: int = 0
    color_brightness: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    red: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    green: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    blue: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    white: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    color_temperature: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    cold_white: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    warm_white: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    effect: str = ""


# ==================== SENSOR ====================
class SensorStateClass(APIIntEnum):
    NONE = 0
    MEASUREMENT = 1
    TOTAL_INCREASING = 2
    TOTAL = 3


class LastResetType(APIIntEnum):
    NONE = 0
    NEVER = 1
    AUTO = 2


@dataclass(frozen=True)
class SensorInfo(EntityInfo):
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
    assumed_state: bool = False
    device_class: str = ""


@dataclass(frozen=True)
class SwitchState(EntityState):
    state: bool = False


# ==================== TEXT SENSOR ====================
@dataclass(frozen=True)
class TextSensorInfo(EntityInfo):
    pass


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
    QUIET = 9


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
    visual_target_temperature_step: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    visual_current_temperature_step: float = converter_field(
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
class NumberMode(APIIntEnum):
    AUTO = 0
    BOX = 1
    SLIDER = 2


@dataclass(frozen=True)
class NumberInfo(EntityInfo):
    min_value: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    max_value: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    step: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    unit_of_measurement: str = ""
    mode: Optional[NumberMode] = converter_field(
        default=NumberMode.AUTO, converter=NumberMode.convert
    )
    device_class: str = ""


@dataclass(frozen=True)
class NumberState(EntityState):
    state: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    missing_state: bool = False


# ==================== SELECT ====================
@dataclass(frozen=True)
class SelectInfo(EntityInfo):
    options: List[str] = converter_field(default_factory=list, converter=list)


@dataclass(frozen=True)
class SelectState(EntityState):
    state: str = ""
    missing_state: bool = False


# ==================== SIREN ====================
@dataclass(frozen=True)
class SirenInfo(EntityInfo):
    tones: List[str] = converter_field(default_factory=list, converter=list)
    supports_volume: bool = False
    supports_duration: bool = False


@dataclass(frozen=True)
class SirenState(EntityState):
    state: bool = False


# ==================== BUTTON ====================
@dataclass(frozen=True)
class ButtonInfo(EntityInfo):
    device_class: str = ""


# ==================== LOCK ====================
class LockState(APIIntEnum):
    NONE = 0
    LOCKED = 1
    UNLOCKED = 3
    JAMMED = 3
    LOCKING = 4
    UNLOCKING = 5


class LockCommand(APIIntEnum):
    UNLOCK = 0
    LOCK = 1
    OPEN = 2


@dataclass(frozen=True)
class LockInfo(EntityInfo):
    supports_open: bool = False
    assumed_state: bool = False

    requires_code: bool = False
    code_format: str = ""


@dataclass(frozen=True)
class LockEntityState(EntityState):
    state: Optional[LockState] = converter_field(
        default=LockState.NONE, converter=LockState.convert
    )


# ==================== MEDIA PLAYER ====================
class MediaPlayerState(APIIntEnum):
    NONE = 0
    IDLE = 1
    PLAYING = 2
    PAUSED = 3


class MediaPlayerCommand(APIIntEnum):
    PLAY = 0
    PAUSE = 1
    STOP = 2
    MUTE = 3
    UNMUTE = 4


@dataclass(frozen=True)
class MediaPlayerInfo(EntityInfo):
    supports_pause: bool = False


@dataclass(frozen=True)
class MediaPlayerEntityState(EntityState):
    state: Optional[MediaPlayerState] = converter_field(
        default=MediaPlayerState.NONE, converter=MediaPlayerState.convert
    )
    volume: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    muted: bool = False


# ==================== INFO MAP ====================

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
    "button": ButtonInfo,
    "lock": LockInfo,
    "media_player": MediaPlayerInfo,
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


# ==================== BLUETOOTH ====================


def _join_split_uuid(value: List[int]) -> str:
    """Convert a high/low uuid into a single string."""
    return str(UUID(int=(value[0] << 64) | value[1]))


def _uuid_converter(uuid: str) -> str:
    return (
        f"0000{uuid[2:].lower()}-0000-1000-8000-00805f9b34fb"
        if len(uuid) < 8
        else uuid.lower()
    )


_cached_uuid_converter = lru_cache(maxsize=128)(_uuid_converter)


# value is likely a google.protobuf.pyext._message.RepeatedScalarContainer
def _convert_bluetooth_le_service_uuids(value: Iterable[str]) -> List[str]:
    if not value:
        # empty list, don't convert
        return []

    return [_cached_uuid_converter(v) for v in value]


def _convert_bluetooth_le_service_data(
    value: Union[Dict[str, bytes], Collection["BluetoothServiceData"]],
) -> Dict[str, bytes]:
    # We literally mean is a `dict` not any other class
    if type(value) is dict:  # pylint: disable=unidiomatic-typecheck
        return value

    if not value:
        return {}

    # v.data if v.data else v.legacy_data is backwards compatible with ESPHome devices before 2022.10.0
    if value[0].data:  # type: ignore
        return {
            _cached_uuid_converter(v.uuid): bytes(v.data)  # type: ignore[union-attr]
            for v in value
        }

    return {
        _cached_uuid_converter(v.uuid): bytes(v.legacy_data)  # type: ignore[union-attr]
        for v in value
    }


def _convert_bluetooth_le_manufacturer_data(
    value: Union[Dict[int, bytes], Collection["BluetoothServiceData"]],
) -> Dict[int, bytes]:
    # We literally mean is a `dict` not any other class
    if type(value) is dict:  # pylint: disable=unidiomatic-typecheck
        return value

    if not value:
        return {}

    # v.data if v.data else v.legacy_data is backwards compatible with ESPHome devices before 2022.10.0
    if value[0].data:  # type: ignore
        return {int(v.uuid, 16): bytes(v.data) for v in value}  # type: ignore

    return {int(v.uuid, 16): bytes(v.legacy_data) for v in value}  # type: ignore


@_dataclass_decorator
class BluetoothLEAdvertisement:
    address: int
    rssi: int
    address_type: int
    name: str
    service_uuids: List[str]
    service_data: Dict[str, bytes]
    manufacturer_data: Dict[int, bytes]

    @classmethod
    def from_pb(  # type: ignore[misc]
        cls: "BluetoothLEAdvertisement", data: "BluetoothLEAdvertisementResponse"
    ) -> "BluetoothLEAdvertisement":
        return cls(  # type: ignore[operator, no-any-return]
            address=data.address,
            rssi=data.rssi,
            address_type=data.address_type,
            name=data.name.decode("utf-8", errors="replace"),
            service_uuids=_convert_bluetooth_le_service_uuids(data.service_uuids),
            service_data=_convert_bluetooth_le_service_data(data.service_data),
            manufacturer_data=_convert_bluetooth_le_manufacturer_data(
                data.manufacturer_data
            ),
        )


@dataclass(frozen=True)
class BluetoothDeviceConnection(APIModelBase):
    address: int = 0
    connected: bool = False
    mtu: int = 0
    error: int = 0


@dataclass(frozen=True)
class BluetoothDevicePairing(APIModelBase):
    address: int = 0
    paired: bool = False
    error: int = 0


@dataclass(frozen=True)
class BluetoothDeviceUnpairing(APIModelBase):
    address: int = 0
    success: bool = False
    error: int = 0


@dataclass(frozen=True)
class BluetoothDeviceClearCache(APIModelBase):
    address: int = 0
    success: bool = False
    error: int = 0


@dataclass(frozen=True)
class BluetoothGATTRead(APIModelBase):
    address: int = 0
    handle: int = 0

    data: bytes = field(default_factory=bytes)


@dataclass(frozen=True)
class BluetoothGATTDescriptor(APIModelBase):
    uuid: str = converter_field(default="", converter=_join_split_uuid)
    handle: int = 0

    @classmethod
    def convert_list(cls, value: List[Any]) -> List["BluetoothGATTDescriptor"]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(cls.from_dict(x))
            else:
                ret.append(cls.from_pb(x))
        return ret


@dataclass(frozen=True)
class BluetoothGATTCharacteristic(APIModelBase):
    uuid: str = converter_field(default="", converter=_join_split_uuid)
    handle: int = 0
    properties: int = 0

    descriptors: List[BluetoothGATTDescriptor] = converter_field(
        default_factory=list, converter=BluetoothGATTDescriptor.convert_list
    )

    @classmethod
    def convert_list(cls, value: List[Any]) -> List["BluetoothGATTCharacteristic"]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(cls.from_dict(x))
            else:
                ret.append(cls.from_pb(x))
        return ret


@dataclass(frozen=True)
class BluetoothGATTService(APIModelBase):
    uuid: str = converter_field(default="", converter=_join_split_uuid)
    handle: int = 0
    characteristics: List[BluetoothGATTCharacteristic] = converter_field(
        default_factory=list, converter=BluetoothGATTCharacteristic.convert_list
    )

    @classmethod
    def convert_list(cls, value: List[Any]) -> List["BluetoothGATTService"]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(cls.from_dict(x))
            else:
                ret.append(cls.from_pb(x))
        return ret


@dataclass(frozen=True)
class BluetoothGATTServices(APIModelBase):
    address: int = 0
    services: List[BluetoothGATTService] = converter_field(
        default_factory=list, converter=BluetoothGATTService.convert_list
    )


@dataclass(frozen=True)
class ESPHomeBluetoothGATTServices:
    address: int = 0
    services: List[BluetoothGATTService] = field(default_factory=list)


@dataclass(frozen=True)
class BluetoothConnectionsFree(APIModelBase):
    free: int = 0
    limit: int = 0


@dataclass(frozen=True)
class BluetoothGATTError(APIModelBase):
    address: int = 0
    handle: int = 0
    error: int = 0


class BluetoothDeviceRequestType(APIIntEnum):
    CONNECT = 0
    DISCONNECT = 1
    PAIR = 2
    UNPAIR = 3
    CONNECT_V3_WITH_CACHE = 4
    CONNECT_V3_WITHOUT_CACHE = 5
    CLEAR_CACHE = 6


@dataclass(frozen=True)
class VoiceAssistantCommand(APIModelBase):
    start: bool = False


class LogLevel(APIIntEnum):
    LOG_LEVEL_NONE = 0
    LOG_LEVEL_ERROR = 1
    LOG_LEVEL_WARN = 2
    LOG_LEVEL_INFO = 3
    LOG_LEVEL_CONFIG = 4
    LOG_LEVEL_DEBUG = 5
    LOG_LEVEL_VERBOSE = 6
    LOG_LEVEL_VERY_VERBOSE = 7


class VoiceAssistantEventType(APIIntEnum):
    VOICE_ASSISTANT_ERROR = 0
    VOICE_ASSISTANT_RUN_START = 1
    VOICE_ASSISTANT_RUN_END = 2
    VOICE_ASSISTANT_STT_START = 3
    VOICE_ASSISTANT_STT_END = 4
    VOICE_ASSISTANT_INTENT_START = 5
    VOICE_ASSISTANT_INTENT_END = 6
    VOICE_ASSISTANT_TTS_START = 7
    VOICE_ASSISTANT_TTS_END = 8
