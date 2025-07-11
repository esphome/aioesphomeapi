from __future__ import annotations

from collections.abc import Iterable
import contextlib
from dataclasses import asdict, dataclass, field, fields
import enum
from functools import cache, lru_cache, partial
import sys
from typing import TYPE_CHECKING, Any, Callable, TypeVar, cast
from uuid import UUID

from google.protobuf import message

from .util import fix_float_single_double_conversion

if sys.version_info[:2] < (3, 10):
    _dataclass_decorator = dataclass
    _frozen_dataclass_decorator = partial(dataclass, frozen=True)
else:
    _dataclass_decorator = partial(dataclass, slots=True)
    _frozen_dataclass_decorator = partial(dataclass, frozen=True, slots=True)


if TYPE_CHECKING:
    from .api_pb2 import (  # type: ignore
        BluetoothLEAdvertisementResponse,
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
    def convert(cls: type[_T], value: int) -> _T | None:
        try:
            return cls(value)
        except ValueError:
            return None

    @classmethod
    def convert_list(cls: type[_T], value: list[int]) -> list[_T]:
        ret = []
        for x in value:
            with contextlib.suppress(ValueError):
                ret.append(cls(x))
        return ret


# Fields do not change so we can cache the result
# of calling fields() on the dataclass
cached_fields = cache(fields)


@_frozen_dataclass_decorator
class APIModelBase:
    def __post_init__(self) -> None:
        for field_ in cached_fields(type(self)):  # type: ignore[arg-type]
            convert = field_.metadata.get("converter")
            if convert is None:
                continue
            val = getattr(self, field_.name)
            # use this setattr to prevent FrozenInstanceError
            object.__setattr__(self, field_.name, convert(val))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[no-any-return, call-overload]

    @classmethod
    def from_dict(
        cls: type[_V], data: dict[str, Any], *, ignore_missing: bool = True
    ) -> _V:
        return cls(
            **{
                f.name: data[f.name]
                for f in cached_fields(cls)  # type: ignore[arg-type]
                if f.name in data or (not ignore_missing)
            }
        )

    @classmethod
    def from_pb(cls: type[_V], data: Any) -> _V:
        return cls(**{f.name: getattr(data, f.name) for f in cached_fields(cls)})  # type: ignore[arg-type]


def converter_field(*, converter: Callable[[Any], _V], **kwargs: Any) -> _V:
    metadata = kwargs.pop("metadata", {})
    metadata["converter"] = converter
    return cast(
        _V,
        field(metadata=metadata, **kwargs),  # pylint: disable=invalid-field-call
    )


@dataclass(frozen=True, order=True)
class APIVersion(APIModelBase):
    major: int = 0
    minor: int = 0


class BluetoothProxyFeature(enum.IntFlag):
    PASSIVE_SCAN = 1 << 0
    ACTIVE_CONNECTIONS = 1 << 1
    REMOTE_CACHING = 1 << 2
    PAIRING = 1 << 3
    CACHE_CLEARING = 1 << 4
    RAW_ADVERTISEMENTS = 1 << 5
    FEATURE_STATE_AND_MODE = 1 << 6


class BluetoothProxySubscriptionFlag(enum.IntFlag):
    RAW_ADVERTISEMENTS = 1 << 0


class VoiceAssistantFeature(enum.IntFlag):
    VOICE_ASSISTANT = 1 << 0
    SPEAKER = 1 << 1
    API_AUDIO = 1 << 2
    TIMERS = 1 << 3
    ANNOUNCE = 1 << 4
    START_CONVERSATION = 1 << 5


class VoiceAssistantSubscriptionFlag(enum.IntFlag):
    API_AUDIO = 1 << 2


@_frozen_dataclass_decorator
class AreaInfo(APIModelBase):
    area_id: int = 0
    name: str = ""

    @classmethod
    def convert_list(cls, value: list[Any]) -> list[AreaInfo]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(AreaInfo.from_dict(x))
            else:
                ret.append(AreaInfo.from_pb(x))
        return ret

    @classmethod
    def convert(cls, value: Any) -> AreaInfo:
        if isinstance(value, dict):
            return cls.from_dict(value)
        return cls.from_pb(value)


@_frozen_dataclass_decorator
class SubDeviceInfo(APIModelBase):
    device_id: int = 0
    name: str = ""
    area_id: int = 0

    @classmethod
    def convert_list(cls, value: list[Any]) -> list[SubDeviceInfo]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(SubDeviceInfo.from_dict(x))
            else:
                ret.append(SubDeviceInfo.from_pb(x))
        return ret


@_frozen_dataclass_decorator
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
    legacy_voice_assistant_version: int = 0
    voice_assistant_feature_flags: int = 0
    legacy_bluetooth_proxy_version: int = 0
    bluetooth_proxy_feature_flags: int = 0
    suggested_area: str = ""
    bluetooth_mac_address: str = ""
    api_encryption_supported: bool = False
    devices: list[SubDeviceInfo] = converter_field(
        default_factory=list, converter=SubDeviceInfo.convert_list
    )
    areas: list[AreaInfo] = converter_field(
        default_factory=list, converter=AreaInfo.convert_list
    )
    area: AreaInfo = converter_field(
        default_factory=AreaInfo, converter=AreaInfo.convert
    )

    def bluetooth_proxy_feature_flags_compat(self, api_version: APIVersion) -> int:
        if api_version < APIVersion(1, 9):
            flags: int = 0
            if self.legacy_bluetooth_proxy_version >= 1:
                flags |= BluetoothProxyFeature.PASSIVE_SCAN
            if self.legacy_bluetooth_proxy_version >= 2:
                flags |= BluetoothProxyFeature.ACTIVE_CONNECTIONS
            if self.legacy_bluetooth_proxy_version >= 3:
                flags |= BluetoothProxyFeature.REMOTE_CACHING
            if self.legacy_bluetooth_proxy_version >= 4:
                flags |= BluetoothProxyFeature.PAIRING
            if self.legacy_bluetooth_proxy_version >= 5:
                flags |= BluetoothProxyFeature.CACHE_CLEARING
            return flags
        return self.bluetooth_proxy_feature_flags

    def voice_assistant_feature_flags_compat(self, api_version: APIVersion) -> int:
        if api_version < APIVersion(1, 10):
            flags: int = 0
            if self.legacy_voice_assistant_version >= 1:
                flags |= VoiceAssistantFeature.VOICE_ASSISTANT
            if self.legacy_voice_assistant_version == 2:
                flags |= VoiceAssistantFeature.SPEAKER
            return flags
        return self.voice_assistant_feature_flags


class EntityCategory(APIIntEnum):
    NONE = 0
    CONFIG = 1
    DIAGNOSTIC = 2


@_frozen_dataclass_decorator
class EntityInfo(APIModelBase):
    object_id: str = ""
    key: int = 0
    name: str = ""
    unique_id: str = ""
    disabled_by_default: bool = False
    icon: str = ""
    entity_category: EntityCategory | None = converter_field(
        default=EntityCategory.NONE, converter=EntityCategory.convert
    )
    device_id: int = 0


@_frozen_dataclass_decorator
class EntityState(APIModelBase):
    key: int = 0
    device_id: int = 0


@_frozen_dataclass_decorator
class CommandProtoMessage(APIModelBase):
    key: int = 0
    device_id: int = 0


# ==================== BINARY SENSOR ====================
@_frozen_dataclass_decorator
class BinarySensorInfo(EntityInfo):
    device_class: str = ""
    is_status_binary_sensor: bool = False


@_frozen_dataclass_decorator
class BinarySensorState(EntityState):
    state: bool = False
    missing_state: bool = False


# ==================== COVER ====================
@_frozen_dataclass_decorator
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


@_frozen_dataclass_decorator
class CoverState(EntityState):
    legacy_state: LegacyCoverState | None = converter_field(
        default=LegacyCoverState.OPEN, converter=LegacyCoverState.convert
    )
    position: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    tilt: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    current_operation: CoverOperation | None = converter_field(
        default=CoverOperation.IDLE, converter=CoverOperation.convert
    )

    def is_closed(self, api_version: APIVersion) -> bool:
        if api_version < APIVersion(1, 1):
            return self.legacy_state == LegacyCoverState.CLOSED
        return self.position == 0.0


# ==================== EVENT ==================
@_frozen_dataclass_decorator
class EventInfo(EntityInfo):
    device_class: str = ""
    event_types: list[str] = converter_field(default_factory=list, converter=list)


@_frozen_dataclass_decorator
class Event(EntityState):
    event_type: str = ""


# ==================== FAN ====================
@_frozen_dataclass_decorator
class FanInfo(EntityInfo):
    supports_oscillation: bool = False
    supports_speed: bool = False
    supports_direction: bool = False
    supported_speed_count: int = 0
    supported_preset_modes: list[str] = converter_field(
        default_factory=list, converter=list
    )


class FanSpeed(APIIntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2


class FanDirection(APIIntEnum):
    FORWARD = 0
    REVERSE = 1


@_frozen_dataclass_decorator
class FanState(EntityState):
    state: bool = False
    oscillating: bool = False
    speed: FanSpeed | None = converter_field(
        default=FanSpeed.LOW, converter=FanSpeed.convert
    )
    speed_level: int = 0
    direction: FanDirection | None = converter_field(
        default=FanDirection.FORWARD, converter=FanDirection.convert
    )
    preset_mode: str = ""


# ==================== LIGHT ====================
class LightColorCapability(enum.IntFlag):
    ON_OFF = 1 << 0
    BRIGHTNESS = 1 << 1
    WHITE = 1 << 2
    COLOR_TEMPERATURE = 1 << 3
    COLD_WARM_WHITE = 1 << 4
    RGB = 1 << 5


class ColorMode(APIIntEnum):
    UNKNOWN = 0
    ON_OFF = 1
    LEGACY_BRIGHTNESS = 2
    BRIGHTNESS = 3
    WHITE = 7
    COLOR_TEMPERATURE = 11
    COLD_WARM_WHITE = 19
    RGB = 35
    RGB_WHITE = 39
    RGB_COLOR_TEMPERATURE = 47
    RGB_COLD_WARM_WHITE = 51


@_frozen_dataclass_decorator
class LightInfo(EntityInfo):
    supported_color_modes: list[ColorMode] = converter_field(
        default_factory=list, converter=ColorMode.convert_list
    )
    min_mireds: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    max_mireds: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    effects: list[str] = converter_field(default_factory=list, converter=list)

    # deprecated, do not use
    legacy_supports_brightness: bool = False
    legacy_supports_rgb: bool = False
    legacy_supports_white_value: bool = False
    legacy_supports_color_temperature: bool = False

    def supported_color_modes_compat(self, api_version: APIVersion) -> list[ColorMode]:
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

            return cast(list[ColorMode], modes_map[key]) if key in modes_map else []

        return self.supported_color_modes


@_frozen_dataclass_decorator
class LightState(EntityState):
    state: bool = False
    brightness: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    color_mode: ColorMode = ColorMode.UNKNOWN
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


@_frozen_dataclass_decorator
class SensorInfo(EntityInfo):
    device_class: str = ""
    unit_of_measurement: str = ""
    accuracy_decimals: int = 0
    force_update: bool = False
    state_class: SensorStateClass | None = converter_field(
        default=SensorStateClass.NONE, converter=SensorStateClass.convert
    )
    legacy_last_reset_type: LastResetType | None = converter_field(
        default=LastResetType.NONE, converter=LastResetType.convert
    )


@_frozen_dataclass_decorator
class SensorState(EntityState):
    state: float = 0.0
    missing_state: bool = False


# ==================== SWITCH ====================
@_frozen_dataclass_decorator
class SwitchInfo(EntityInfo):
    assumed_state: bool = False
    device_class: str = ""


@_frozen_dataclass_decorator
class SwitchState(EntityState):
    state: bool = False


# ==================== TEXT SENSOR ====================
@_frozen_dataclass_decorator
class TextSensorInfo(EntityInfo):
    device_class: str = ""


@_frozen_dataclass_decorator
class TextSensorState(EntityState):
    state: str = ""
    missing_state: bool = False


# ==================== CAMERA ====================
@_frozen_dataclass_decorator
class CameraInfo(EntityInfo):
    pass


@_frozen_dataclass_decorator
class CameraState(EntityState):
    data: bytes = field(default_factory=bytes)  # pylint: disable=invalid-field-call


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


@_frozen_dataclass_decorator
class ClimateInfo(EntityInfo):
    supports_current_temperature: bool = False
    supports_two_point_target_temperature: bool = False
    supported_modes: list[ClimateMode] = converter_field(
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
    supported_fan_modes: list[ClimateFanMode] = converter_field(
        default_factory=list, converter=ClimateFanMode.convert_list
    )
    supported_swing_modes: list[ClimateSwingMode] = converter_field(
        default_factory=list, converter=ClimateSwingMode.convert_list
    )
    supported_custom_fan_modes: list[str] = converter_field(
        default_factory=list, converter=list
    )
    supported_presets: list[ClimatePreset] = converter_field(
        default_factory=list, converter=ClimatePreset.convert_list
    )
    supported_custom_presets: list[str] = converter_field(
        default_factory=list, converter=list
    )
    supports_current_humidity: bool = False
    supports_target_humidity: bool = False
    visual_min_humidity: float = 0
    visual_max_humidity: float = 0

    def supported_presets_compat(self, api_version: APIVersion) -> list[ClimatePreset]:
        if api_version < APIVersion(1, 5):
            return (
                [ClimatePreset.HOME, ClimatePreset.AWAY]
                if self.legacy_supports_away
                else []
            )
        return self.supported_presets


@_frozen_dataclass_decorator
class ClimateState(EntityState):
    mode: ClimateMode | None = converter_field(
        default=ClimateMode.OFF, converter=ClimateMode.convert
    )
    action: ClimateAction | None = converter_field(
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
    unused_legacy_away: bool = False
    fan_mode: ClimateFanMode | None = converter_field(
        default=ClimateFanMode.ON, converter=ClimateFanMode.convert
    )
    swing_mode: ClimateSwingMode | None = converter_field(
        default=ClimateSwingMode.OFF, converter=ClimateSwingMode.convert
    )
    custom_fan_mode: str = ""
    preset: ClimatePreset | None = converter_field(
        default=ClimatePreset.NONE, converter=ClimatePreset.convert
    )
    custom_preset: str = ""
    current_humidity: float = 0
    target_humidity: float = 0

    def preset_compat(self, api_version: APIVersion) -> ClimatePreset | None:
        if api_version < APIVersion(1, 5):
            return ClimatePreset.AWAY if self.unused_legacy_away else ClimatePreset.HOME
        return self.preset


# ==================== NUMBER ====================
class NumberMode(APIIntEnum):
    AUTO = 0
    BOX = 1
    SLIDER = 2


@_frozen_dataclass_decorator
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
    mode: NumberMode | None = converter_field(
        default=NumberMode.AUTO, converter=NumberMode.convert
    )
    device_class: str = ""


@_frozen_dataclass_decorator
class NumberState(EntityState):
    state: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    missing_state: bool = False


# ==================== DATETIME DATE ====================


@_frozen_dataclass_decorator
class DateInfo(EntityInfo):
    pass


@_frozen_dataclass_decorator
class DateState(EntityState):
    missing_state: bool = False
    year: int = 0
    month: int = 0
    day: int = 0


# ==================== DATETIME TIME ====================


@_frozen_dataclass_decorator
class TimeInfo(EntityInfo):
    pass


@_frozen_dataclass_decorator
class TimeState(EntityState):
    missing_state: bool = False
    hour: int = 0
    minute: int = 0
    second: int = 0


# ==================== DATETIME DATETIME ====================
@_frozen_dataclass_decorator
class DateTimeInfo(EntityInfo):
    pass


@_frozen_dataclass_decorator
class DateTimeState(EntityState):
    missing_state: bool = False
    epoch_seconds: int = 0


# ==================== SELECT ====================
@_frozen_dataclass_decorator
class SelectInfo(EntityInfo):
    options: list[str] = converter_field(default_factory=list, converter=list)


@_frozen_dataclass_decorator
class SelectState(EntityState):
    state: str = ""
    missing_state: bool = False


# ==================== SIREN ====================
@_frozen_dataclass_decorator
class SirenInfo(EntityInfo):
    tones: list[str] = converter_field(default_factory=list, converter=list)
    supports_volume: bool = False
    supports_duration: bool = False


@_frozen_dataclass_decorator
class SirenState(EntityState):
    state: bool = False


# ==================== BUTTON ====================
@_frozen_dataclass_decorator
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


@_frozen_dataclass_decorator
class LockInfo(EntityInfo):
    supports_open: bool = False
    assumed_state: bool = False

    requires_code: bool = False
    code_format: str = ""


@_frozen_dataclass_decorator
class LockEntityState(EntityState):
    state: LockState | None = converter_field(
        default=LockState.NONE, converter=LockState.convert
    )


# ==================== VALVE ====================
@_frozen_dataclass_decorator
class ValveInfo(EntityInfo):
    device_class: str = ""
    assumed_state: bool = False
    supports_stop: bool = False
    supports_position: bool = False


class ValveOperation(APIIntEnum):
    IDLE = 0
    IS_OPENING = 1
    IS_CLOSING = 2


@_frozen_dataclass_decorator
class ValveState(EntityState):
    position: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    current_operation: ValveOperation | None = converter_field(
        default=ValveOperation.IDLE, converter=ValveOperation.convert
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


class MediaPlayerFormatPurpose(APIIntEnum):
    DEFAULT = 0
    ANNOUNCEMENT = 1


@_frozen_dataclass_decorator
class MediaPlayerSupportedFormat(APIModelBase):
    format: str
    sample_rate: int
    num_channels: int
    purpose: MediaPlayerFormatPurpose | None = converter_field(
        default=MediaPlayerFormatPurpose.DEFAULT,
        converter=MediaPlayerFormatPurpose.convert,
    )
    sample_bytes: int = 0

    @classmethod
    def convert_list(cls, value: list[Any]) -> list[MediaPlayerSupportedFormat]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(MediaPlayerSupportedFormat.from_dict(x))
            else:
                ret.append(MediaPlayerSupportedFormat.from_pb(x))
        return ret


@_frozen_dataclass_decorator
class MediaPlayerInfo(EntityInfo):
    supports_pause: bool = False

    supported_formats: list[MediaPlayerSupportedFormat] = converter_field(
        default_factory=list, converter=MediaPlayerSupportedFormat.convert_list
    )


@_frozen_dataclass_decorator
class MediaPlayerEntityState(EntityState):
    state: MediaPlayerState | None = converter_field(
        default=MediaPlayerState.NONE, converter=MediaPlayerState.convert
    )
    volume: float = converter_field(
        default=0.0, converter=fix_float_single_double_conversion
    )
    muted: bool = False


# ==================== ALARM CONTROL PANEL ====================
class AlarmControlPanelState(APIIntEnum):
    DISARMED = 0
    ARMED_HOME = 1
    ARMED_AWAY = 2
    ARMED_NIGHT = 3
    ARMED_VACATION = 4
    ARMED_CUSTOM_BYPASS = 5
    PENDING = 6
    ARMING = 7
    DISARMING = 8
    TRIGGERED = 9


class AlarmControlPanelCommand(APIIntEnum):
    DISARM = 0
    ARM_AWAY = 1
    ARM_HOME = 2
    ARM_NIGHT = 3
    ARM_VACATION = 4
    ARM_CUSTOM_BYPASS = 5
    TRIGGER = 6


@_frozen_dataclass_decorator
class AlarmControlPanelInfo(EntityInfo):
    supported_features: int = 0
    requires_code: bool = False
    requires_code_to_arm: bool = False


@_frozen_dataclass_decorator
class AlarmControlPanelEntityState(EntityState):
    state: AlarmControlPanelState | None = converter_field(
        default=AlarmControlPanelState.DISARMED,
        converter=AlarmControlPanelState.convert,
    )


# ==================== TEXT ====================
class TextMode(APIIntEnum):
    TEXT = 0
    PASSWORD = 1


@_frozen_dataclass_decorator
class TextInfo(EntityInfo):
    min_length: int = 0
    max_length: int = 255
    pattern: str = ""
    mode: TextMode | None = converter_field(
        default=TextMode.TEXT, converter=TextMode.convert
    )


@_frozen_dataclass_decorator
class TextState(EntityState):
    state: str = ""
    missing_state: bool = False


# ==================== UPDATE ====================


class UpdateCommand(APIIntEnum):
    NONE = 0
    INSTALL = 1
    CHECK = 2


@_frozen_dataclass_decorator
class UpdateInfo(EntityInfo):
    device_class: str = ""


@_frozen_dataclass_decorator
class UpdateState(EntityState):
    missing_state: bool = False
    in_progress: bool = False
    has_progress: bool = False
    progress: float = 0.0
    current_version: str = ""
    latest_version: str = ""
    title: str = ""
    release_summary: str = ""
    release_url: str = ""


# ==================== INFO MAP ====================

COMPONENT_TYPE_TO_INFO: dict[str, type[EntityInfo]] = {
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
    "date": DateInfo,
    "datetime": DateTimeInfo,
    "select": SelectInfo,
    "siren": SirenInfo,
    "button": ButtonInfo,
    "lock": LockInfo,
    "media_player": MediaPlayerInfo,
    "alarm_control_panel": AlarmControlPanelInfo,
    "text": TextInfo,
    "time": TimeInfo,
    "valve": ValveInfo,
    "event": EventInfo,
    "update": UpdateInfo,
}


# ==================== USER-DEFINED SERVICES ====================
def _convert_homeassistant_service_map(
    value: dict[str, str] | Iterable[HomeassistantServiceMap],
) -> dict[str, str]:
    if isinstance(value, dict):
        # already a dict, don't convert
        return value
    return {v.key: v.value for v in value}  # type: ignore


@_frozen_dataclass_decorator
class HomeassistantServiceCall(APIModelBase):
    service: str = ""
    is_event: bool = False
    data: dict[str, str] = converter_field(
        default_factory=dict, converter=_convert_homeassistant_service_map
    )
    data_template: dict[str, str] = converter_field(
        default_factory=dict, converter=_convert_homeassistant_service_map
    )
    variables: dict[str, str] = converter_field(
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


@_frozen_dataclass_decorator
class UserServiceArg(APIModelBase):
    name: str = ""
    type: UserServiceArgType | None = converter_field(
        default=UserServiceArgType.BOOL, converter=UserServiceArgType.convert
    )

    @classmethod
    def convert_list(cls, value: list[Any]) -> list[UserServiceArg]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                if "type_" in x and "type" not in x:
                    x = {**x, "type": x["type_"]}
                ret.append(UserServiceArg.from_dict(x))
            else:
                ret.append(UserServiceArg.from_pb(x))
        return ret


@_frozen_dataclass_decorator
class UserService(APIModelBase):
    name: str = ""
    key: int = 0
    args: list[UserServiceArg] = converter_field(
        default_factory=list, converter=UserServiceArg.convert_list
    )


# ==================== BLUETOOTH ====================


def _join_split_uuid(value: list[int]) -> str:
    """Convert a high/low uuid into a single string."""
    return _join_split_uuid_high_low(value[0], value[1])


@lru_cache(maxsize=256)
def _join_split_uuid_high_low(high: int, low: int) -> str:
    return str(UUID(int=(high << 64) | low))


def _uuid_converter(uuid: str) -> str:
    return (
        f"0000{uuid[2:].lower()}-0000-1000-8000-00805f9b34fb"
        if len(uuid) < 8
        else uuid.lower()
    )


_cached_uuid_converter = lru_cache(maxsize=128)(_uuid_converter)


@_dataclass_decorator
class BluetoothLEAdvertisement:
    address: int
    rssi: int
    address_type: int
    name: str
    service_uuids: list[str]
    service_data: dict[str, bytes]
    manufacturer_data: dict[int, bytes]

    @classmethod
    def from_pb(  # type: ignore[misc]
        cls: BluetoothLEAdvertisement, data: BluetoothLEAdvertisementResponse
    ) -> BluetoothLEAdvertisement:
        _uuid_convert = _cached_uuid_converter

        if raw_manufacturer_data := data.manufacturer_data:
            if raw_manufacturer_data[0].data:
                manufacturer_data = {
                    int(v.uuid, 16): v.data for v in raw_manufacturer_data
                }
            else:
                # Legacy data
                manufacturer_data = {
                    int(v.uuid, 16): bytes(v.legacy_data) for v in raw_manufacturer_data
                }
        else:
            manufacturer_data = {}

        if raw_service_data := data.service_data:
            if raw_service_data[0].data:
                service_data = {_uuid_convert(v.uuid): v.data for v in raw_service_data}
            else:
                # Legacy data
                service_data = {
                    _uuid_convert(v.uuid): bytes(v.legacy_data)
                    for v in raw_service_data
                }
        else:
            service_data = {}

        if raw_service_uuids := data.service_uuids:
            service_uuids = [_uuid_convert(v) for v in raw_service_uuids]
        else:
            service_uuids = []

        return cls(  # type: ignore[operator, no-any-return]
            address=data.address,
            rssi=data.rssi,
            address_type=data.address_type,
            name=data.name.decode("utf-8", errors="replace"),
            service_uuids=service_uuids,
            service_data=service_data,
            manufacturer_data=manufacturer_data,
        )


@_frozen_dataclass_decorator
class BluetoothDeviceConnection(APIModelBase):
    address: int = 0
    connected: bool = False
    mtu: int = 0
    error: int = 0


@_frozen_dataclass_decorator
class BluetoothDevicePairing(APIModelBase):
    address: int = 0
    paired: bool = False
    error: int = 0


@_frozen_dataclass_decorator
class BluetoothDeviceUnpairing(APIModelBase):
    address: int = 0
    success: bool = False
    error: int = 0


@_frozen_dataclass_decorator
class BluetoothDeviceClearCache(APIModelBase):
    address: int = 0
    success: bool = False
    error: int = 0


@_frozen_dataclass_decorator
class BluetoothGATTRead(APIModelBase):
    address: int = 0
    handle: int = 0

    data: bytes = field(default_factory=bytes)  # pylint: disable=invalid-field-call


@_frozen_dataclass_decorator
class BluetoothGATTDescriptor(APIModelBase):
    uuid: str = converter_field(default="", converter=_join_split_uuid)
    handle: int = 0

    @classmethod
    def convert_list(cls, value: list[Any]) -> list[BluetoothGATTDescriptor]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(cls.from_dict(x))
            else:
                ret.append(cls.from_pb(x))
        return ret


@_frozen_dataclass_decorator
class BluetoothGATTCharacteristic(APIModelBase):
    uuid: str = converter_field(default="", converter=_join_split_uuid)
    handle: int = 0
    properties: int = 0

    descriptors: list[BluetoothGATTDescriptor] = converter_field(
        default_factory=list, converter=BluetoothGATTDescriptor.convert_list
    )

    @classmethod
    def convert_list(cls, value: list[Any]) -> list[BluetoothGATTCharacteristic]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(cls.from_dict(x))
            else:
                ret.append(cls.from_pb(x))
        return ret


@_frozen_dataclass_decorator
class BluetoothGATTService(APIModelBase):
    uuid: str = converter_field(default="", converter=_join_split_uuid)
    handle: int = 0
    characteristics: list[BluetoothGATTCharacteristic] = converter_field(
        default_factory=list, converter=BluetoothGATTCharacteristic.convert_list
    )

    @classmethod
    def convert_list(cls, value: list[Any]) -> list[BluetoothGATTService]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(cls.from_dict(x))
            else:
                ret.append(cls.from_pb(x))
        return ret


@_frozen_dataclass_decorator
class BluetoothGATTServices(APIModelBase):
    address: int = 0
    services: list[BluetoothGATTService] = converter_field(
        default_factory=list, converter=BluetoothGATTService.convert_list
    )


@_frozen_dataclass_decorator
class ESPHomeBluetoothGATTServices:
    address: int = 0
    services: list[BluetoothGATTService] = field(  # pylint: disable=invalid-field-call
        default_factory=list
    )


@_frozen_dataclass_decorator
class BluetoothConnectionsFree(APIModelBase):
    free: int = 0
    limit: int = 0


@_frozen_dataclass_decorator
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


class BluetoothScannerState(APIIntEnum):
    IDLE = 0
    STARTING = 1
    RUNNING = 2
    FAILED = 3
    STOPPING = 4
    STOPPED = 5


class BluetoothScannerMode(APIIntEnum):
    PASSIVE = 0
    ACTIVE = 1


@_frozen_dataclass_decorator
class BluetoothScannerStateResponse(APIModelBase):
    state: BluetoothScannerState | None = converter_field(
        default=BluetoothScannerState.IDLE, converter=BluetoothScannerState.convert
    )
    mode: BluetoothScannerMode | None = converter_field(
        default=BluetoothScannerMode.PASSIVE, converter=BluetoothScannerMode.convert
    )


class VoiceAssistantCommandFlag(enum.IntFlag):
    USE_VAD = 1 << 0
    USE_WAKE_WORD = 1 << 1


@_frozen_dataclass_decorator
class VoiceAssistantAudioSettings(APIModelBase):
    noise_suppression_level: int = 0
    auto_gain: int = 0
    volume_multiplier: float = 1.0


@_frozen_dataclass_decorator
class VoiceAssistantCommand(APIModelBase):
    start: bool = False
    conversation_id: str = ""
    flags: int = False
    audio_settings: VoiceAssistantAudioSettings = converter_field(
        default=VoiceAssistantAudioSettings(),
        converter=VoiceAssistantAudioSettings.from_pb,
    )
    wake_word_phrase: str = ""


@_frozen_dataclass_decorator
class VoiceAssistantAudioData(APIModelBase):
    data: bytes = field(default_factory=bytes)  # pylint: disable=invalid-field-call
    end: bool = False


@_frozen_dataclass_decorator
class VoiceAssistantAnnounceFinished(APIModelBase):
    success: bool = False


@_frozen_dataclass_decorator
class VoiceAssistantWakeWord(APIModelBase):
    id: str
    wake_word: str
    trained_languages: list[str]

    @classmethod
    def convert_list(cls, value: list[Any]) -> list[VoiceAssistantWakeWord]:
        ret = []
        for x in value:
            if isinstance(x, dict):
                ret.append(VoiceAssistantWakeWord.from_dict(x))
            else:
                ret.append(VoiceAssistantWakeWord.from_pb(x))
        return ret


@_frozen_dataclass_decorator
class VoiceAssistantConfigurationResponse(APIModelBase):
    available_wake_words: list[VoiceAssistantWakeWord] = converter_field(
        default_factory=list, converter=VoiceAssistantWakeWord.convert_list
    )
    active_wake_words: list[str] = converter_field(default_factory=list, converter=list)
    max_active_wake_words: int = 0


@_frozen_dataclass_decorator
class VoiceAssistantConfigurationRequest(APIModelBase):
    pass


@_frozen_dataclass_decorator
class VoiceAssistantSetConfiguration(APIModelBase):
    active_wake_words: list[int] = converter_field(default_factory=list, converter=list)


@_frozen_dataclass_decorator
class NoiseEncryptionSetKeyRequest(APIModelBase):
    key: bytes = field(default_factory=bytes)  # pylint: disable=invalid-field-call


@_frozen_dataclass_decorator
class NoiseEncryptionSetKeyResponse(APIModelBase):
    success: bool = False


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
    VOICE_ASSISTANT_WAKE_WORD_START = 9
    VOICE_ASSISTANT_WAKE_WORD_END = 10
    VOICE_ASSISTANT_STT_VAD_START = 11
    VOICE_ASSISTANT_STT_VAD_END = 12
    VOICE_ASSISTANT_TTS_STREAM_START = 98
    VOICE_ASSISTANT_TTS_STREAM_END = 99
    VOICE_ASSISTANT_INTENT_PROGRESS = 100


class VoiceAssistantTimerEventType(APIIntEnum):
    VOICE_ASSISTANT_TIMER_STARTED = 0
    VOICE_ASSISTANT_TIMER_UPDATED = 1
    VOICE_ASSISTANT_TIMER_CANCELLED = 2
    VOICE_ASSISTANT_TIMER_FINISHED = 3


_TYPE_TO_NAME = {
    BinarySensorInfo: "binary_sensor",
    ButtonInfo: "button",
    CoverInfo: "cover",
    FanInfo: "fan",
    LightInfo: "light",
    NumberInfo: "number",
    DateInfo: "date",
    DateTimeInfo: "datetime",
    SelectInfo: "select",
    SensorInfo: "sensor",
    SirenInfo: "siren",
    SwitchInfo: "switch",
    TextSensorInfo: "text_sensor",
    CameraInfo: "camera",
    ClimateInfo: "climate",
    LockInfo: "lock",
    MediaPlayerInfo: "media_player",
    AlarmControlPanelInfo: "alarm_control_panel",
    TextInfo: "text_info",
    TimeInfo: "time",
    ValveInfo: "valve",
    EventInfo: "event",
    UpdateInfo: "update",
}


def build_unique_id(formatted_mac: str, entity_info: EntityInfo) -> str:
    """Build a unique id for an entity.

    This is the new format for unique ids which replaces the old format
    that is included in the EntityInfo object. This new format is used
    because the old format used the name in the unique id which is not
    guaranteed to be unique. This new format is guaranteed to be unique
    and is also more human readable.
    """
    # <mac>-<entity type>-<object_id>
    return f"{formatted_mac}-{_TYPE_TO_NAME[type(entity_info)]}-{entity_info.object_id}"


def message_types_to_names(msg_types: Iterable[type[message.Message]]) -> str:
    return ", ".join(t.__name__ for t in msg_types)
