from __future__ import annotations

from dataclasses import dataclass, field

from google.protobuf import message
import pytest

from aioesphomeapi.api_pb2 import (
    AlarmControlPanelStateResponse,
    AreaInfo as AreaInfoProto,
    BinarySensorStateResponse,
    BluetoothGATTCharacteristic,
    BluetoothGATTDescriptor,
    BluetoothGATTGetServicesResponse,
    BluetoothScannerStateResponse,
    ClimateStateResponse,
    CoverStateResponse,
    DateStateResponse,
    DateTimeStateResponse,
    DeviceInfo as SubDeviceInfoProto,
    DeviceInfoResponse,
    EventResponse,
    FanStateResponse,
    HomeassistantServiceMap,
    HomeassistantServiceResponse,
    LightStateResponse,
    ListEntitiesAlarmControlPanelResponse,
    ListEntitiesBinarySensorResponse,
    ListEntitiesButtonResponse,
    ListEntitiesClimateResponse,
    ListEntitiesCoverResponse,
    ListEntitiesDateResponse,
    ListEntitiesDateTimeResponse,
    ListEntitiesEventResponse,
    ListEntitiesFanResponse,
    ListEntitiesLightResponse,
    ListEntitiesLockResponse,
    ListEntitiesMediaPlayerResponse,
    ListEntitiesNumberResponse,
    ListEntitiesSelectResponse,
    ListEntitiesSensorResponse,
    ListEntitiesServicesArgument,
    ListEntitiesServicesResponse,
    ListEntitiesSwitchResponse,
    ListEntitiesTextSensorResponse,
    ListEntitiesTimeResponse,
    ListEntitiesUpdateResponse,
    ListEntitiesValveResponse,
    LockStateResponse,
    MediaPlayerStateResponse,
    MediaPlayerSupportedFormat,
    NoiseEncryptionSetKeyResponse,
    NumberStateResponse,
    SelectStateResponse,
    SensorStateResponse,
    ServiceArgType,
    SirenStateResponse,
    SwitchStateResponse,
    TextSensorStateResponse,
    TextStateResponse,
    TimeStateResponse,
    UpdateStateResponse,
    ValveStateResponse,
)
from aioesphomeapi.model import (
    _TYPE_TO_NAME,
    AlarmControlPanelEntityState,
    AlarmControlPanelInfo,
    APIIntEnum,
    APIModelBase,
    APIVersion,
    AreaInfo,
    BinarySensorInfo,
    BinarySensorState,
    BluetoothGATTCharacteristic as BluetoothGATTCharacteristicModel,
    BluetoothGATTDescriptor as BluetoothGATTDescriptorModel,
    BluetoothGATTService as BluetoothGATTServiceModel,
    BluetoothGATTServices as BluetoothGATTServicesModel,
    BluetoothProxyFeature,
    BluetoothScannerStateResponse as BluetoothScannerStateResponseModel,
    ButtonInfo,
    CameraInfo,
    ClimateInfo,
    ClimatePreset,
    ClimateState,
    ColorMode,
    CoverInfo,
    CoverState,
    DateInfo,
    DateState,
    DateTimeInfo,
    DateTimeState,
    DeviceInfo,
    EntityState,
    Event,
    EventInfo,
    FanInfo,
    FanState,
    HomeassistantServiceCall,
    LegacyCoverState,
    LightColorCapability,
    LightInfo,
    LightState,
    LockEntityState,
    LockInfo,
    MediaPlayerEntityState,
    MediaPlayerInfo,
    NoiseEncryptionSetKeyResponse as NoiseEncryptionSetKeyResponseModel,
    NumberInfo,
    NumberState,
    SelectInfo,
    SelectState,
    SensorInfo,
    SensorState,
    SirenInfo,
    SirenState,
    SubDeviceInfo,
    SwitchInfo,
    SwitchState,
    TextInfo,
    TextSensorInfo,
    TextSensorState,
    TextState,
    TimeInfo,
    TimeState,
    UpdateInfo,
    UpdateState,
    UserService,
    UserServiceArg,
    UserServiceArgType,
    ValveInfo,
    ValveState,
    VoiceAssistantConfigurationResponse,
    VoiceAssistantFeature,
    VoiceAssistantWakeWord,
    build_unique_id,
    converter_field,
)


class DummyIntEnum(APIIntEnum):
    DEFAULT = 0
    MY_VAL = 1


@pytest.mark.parametrize(
    "input, output",
    [
        (0, DummyIntEnum.DEFAULT),
        (1, DummyIntEnum.MY_VAL),
        (2, None),
        (-1, None),
        (DummyIntEnum.DEFAULT, DummyIntEnum.DEFAULT),
        (DummyIntEnum.MY_VAL, DummyIntEnum.MY_VAL),
    ],
)
def test_api_int_enum_convert(input, output):
    v = DummyIntEnum.convert(input)
    assert v == output
    assert v is None or isinstance(v, DummyIntEnum)


@pytest.mark.parametrize(
    "input, output",
    [
        ([], []),
        ([1], [DummyIntEnum.MY_VAL]),
        ([0, 1], [DummyIntEnum.DEFAULT, DummyIntEnum.MY_VAL]),
        ([-1], []),
        ([0, -1], [DummyIntEnum.DEFAULT]),
        ([DummyIntEnum.DEFAULT], [DummyIntEnum.DEFAULT]),
    ],
)
def test_api_int_enum_convert_list(input, output):
    v = DummyIntEnum.convert_list(input)
    assert v == output
    assert all(isinstance(x, DummyIntEnum) for x in v)


@dataclass(frozen=True)
class DummyAPIModel(APIModelBase):
    val1: int = 0
    val2: DummyIntEnum | None = converter_field(  # noqa: RUF009
        default=DummyIntEnum.DEFAULT, converter=DummyIntEnum.convert
    )


@dataclass(frozen=True)
class ListAPIModel(APIModelBase):
    val: list[DummyAPIModel] = field(default_factory=list)


def test_api_model_base_converter():
    assert DummyAPIModel().val2 == DummyIntEnum.DEFAULT
    assert isinstance(DummyAPIModel().val2, DummyIntEnum)
    assert DummyAPIModel(val2=0).val2 == DummyIntEnum.DEFAULT
    assert isinstance(DummyAPIModel().val2, DummyIntEnum)
    assert DummyAPIModel(val2=-1).val2 is None


def test_api_model_base_to_dict():
    assert DummyAPIModel().to_dict() == {
        "val1": 0,
        "val2": 0,
    }
    assert DummyAPIModel(val1=-1, val2=1).to_dict() == {
        "val1": -1,
        "val2": 1,
    }
    assert ListAPIModel(val=[DummyAPIModel()]).to_dict() == {
        "val": [
            {
                "val1": 0,
                "val2": 0,
            }
        ]
    }


def test_api_model_base_from_dict():
    assert DummyAPIModel.from_dict({}) == DummyAPIModel()
    assert DummyAPIModel.from_dict(
        {
            "val1": -1,
            "val2": -1,
        }
    ) == DummyAPIModel(val1=-1, val2=None)
    assert DummyAPIModel.from_dict(
        {
            "val1": -1,
            "unknown": 100,
        }
    ) == DummyAPIModel(val1=-1)
    assert ListAPIModel.from_dict({}) == ListAPIModel()
    assert ListAPIModel.from_dict({"val": []}) == ListAPIModel()


def test_api_model_base_from_pb():
    class DummyPB:
        def __init__(self, val1=0, val2=0):
            self.val1 = val1
            self.val2 = val2

    assert DummyAPIModel.from_pb(DummyPB()) == DummyAPIModel()
    assert DummyAPIModel.from_pb(DummyPB(val1=-1, val2=-1)) == DummyAPIModel(
        val1=-1, val2=None
    )


def test_api_version_ord():
    assert APIVersion(1, 0) == APIVersion(1, 0)
    assert APIVersion(1, 0) < APIVersion(1, 1)
    assert APIVersion(1, 1) <= APIVersion(1, 1)
    assert APIVersion(1, 0) < APIVersion(2, 0)
    assert not (APIVersion(2, 1) <= APIVersion(2, 0))
    assert APIVersion(2, 1) > APIVersion(2, 0)


@pytest.mark.parametrize(
    "model, pb",
    [
        (DeviceInfo, DeviceInfoResponse),
        (BinarySensorInfo, ListEntitiesBinarySensorResponse),
        (BinarySensorState, BinarySensorStateResponse),
        (CoverInfo, ListEntitiesCoverResponse),
        (CoverState, CoverStateResponse),
        (FanInfo, ListEntitiesFanResponse),
        (FanState, FanStateResponse),
        (LightInfo, ListEntitiesLightResponse),
        (LightState, LightStateResponse),
        (SensorInfo, ListEntitiesSensorResponse),
        (SensorState, SensorStateResponse),
        (SwitchInfo, ListEntitiesSwitchResponse),
        (SwitchState, SwitchStateResponse),
        (TextSensorInfo, ListEntitiesTextSensorResponse),
        (TextSensorState, TextSensorStateResponse),
        (ClimateInfo, ListEntitiesClimateResponse),
        (ClimateState, ClimateStateResponse),
        (NumberInfo, ListEntitiesNumberResponse),
        (NumberState, NumberStateResponse),
        (DateInfo, ListEntitiesDateResponse),
        (DateState, DateStateResponse),
        (SelectInfo, ListEntitiesSelectResponse),
        (SelectState, SelectStateResponse),
        (HomeassistantServiceCall, HomeassistantServiceResponse),
        (UserServiceArg, ListEntitiesServicesArgument),
        (UserService, ListEntitiesServicesResponse),
        (ButtonInfo, ListEntitiesButtonResponse),
        (LockInfo, ListEntitiesLockResponse),
        (LockEntityState, LockStateResponse),
        (ValveInfo, ListEntitiesValveResponse),
        (ValveState, ValveStateResponse),
        (MediaPlayerInfo, ListEntitiesMediaPlayerResponse),
        (MediaPlayerEntityState, MediaPlayerStateResponse),
        (AlarmControlPanelInfo, ListEntitiesAlarmControlPanelResponse),
        (AlarmControlPanelEntityState, AlarmControlPanelStateResponse),
        (TextState, TextStateResponse),
        (TimeInfo, ListEntitiesTimeResponse),
        (TimeState, TimeStateResponse),
        (DateTimeInfo, ListEntitiesDateTimeResponse),
        (DateTimeState, DateTimeStateResponse),
        (EventInfo, ListEntitiesEventResponse),
        (Event, EventResponse),
        (UpdateInfo, ListEntitiesUpdateResponse),
        (UpdateState, UpdateStateResponse),
        (NoiseEncryptionSetKeyResponseModel, NoiseEncryptionSetKeyResponse),
        (BluetoothScannerStateResponseModel, BluetoothScannerStateResponse),
    ],
)
def test_basic_pb_conversions(model, pb):
    assert model.from_pb(pb()) == model()


@pytest.mark.parametrize(
    "state, version, out",
    [
        (CoverState(legacy_state=LegacyCoverState.OPEN), (1, 0), False),
        (CoverState(legacy_state=LegacyCoverState.CLOSED), (1, 0), True),
        (CoverState(position=1.0), (1, 1), False),
        (CoverState(position=0.5), (1, 1), False),
        (CoverState(position=0.0), (1, 1), True),
    ],
)
def test_cover_state_legacy_state(state, version, out):
    assert state.is_closed(APIVersion(*version)) is out


@pytest.mark.parametrize(
    "state, version, out",
    [
        (ClimateInfo(legacy_supports_away=False), (1, 4), []),
        (
            ClimateInfo(legacy_supports_away=True),
            (1, 4),
            [ClimatePreset.HOME, ClimatePreset.AWAY],
        ),
        (ClimateInfo(supported_presets=[ClimatePreset.HOME]), (1, 4), []),
        (ClimateInfo(supported_presets=[], legacy_supports_away=True), (1, 5), []),
        (
            ClimateInfo(supported_presets=[ClimatePreset.HOME]),
            (1, 5),
            [ClimatePreset.HOME],
        ),
    ],
)
def test_climate_info_supported_presets_compat(state, version, out):
    assert state.supported_presets_compat(APIVersion(*version)) == out


@pytest.mark.parametrize(
    "state, version, out",
    [
        (ClimateState(unused_legacy_away=False), (1, 4), ClimatePreset.HOME),
        (ClimateState(unused_legacy_away=True), (1, 4), ClimatePreset.AWAY),
        (
            ClimateState(unused_legacy_away=True, preset=ClimatePreset.HOME),
            (1, 4),
            ClimatePreset.AWAY,
        ),
        (ClimateState(preset=ClimatePreset.HOME), (1, 5), ClimatePreset.HOME),
        (ClimateState(preset=ClimatePreset.BOOST), (1, 5), ClimatePreset.BOOST),
        (
            ClimateState(unused_legacy_away=True, preset=ClimatePreset.BOOST),
            (1, 5),
            ClimatePreset.BOOST,
        ),
    ],
)
def test_climate_state_preset_compat(state, version, out):
    assert state.preset_compat(APIVersion(*version)) == out


def test_homeassistant_service_map_conversion():
    assert HomeassistantServiceCall.from_pb(
        HomeassistantServiceResponse(
            data=[HomeassistantServiceMap(key="key", value="value")]
        )
    ) == HomeassistantServiceCall(data={"key": "value"})
    assert HomeassistantServiceCall.from_dict(
        {"data": {"key": "value"}}
    ) == HomeassistantServiceCall(data={"key": "value"})


def test_user_service_conversion():
    assert UserService.from_pb(
        ListEntitiesServicesResponse(
            args=[
                ListEntitiesServicesArgument(
                    name="arg", type=ServiceArgType.SERVICE_ARG_TYPE_INT
                )
            ]
        )
    ) == UserService(args=[UserServiceArg(name="arg", type=UserServiceArgType.INT)])
    assert UserService.from_dict({"args": [{"name": "arg", "type": 1}]}) == UserService(
        args=[UserServiceArg(name="arg", type=UserServiceArgType.INT)]
    )
    assert UserService.from_dict(
        {"args": [{"name": "arg", "type_": 1}]}
    ) == UserService(args=[UserServiceArg(name="arg", type=UserServiceArgType.INT)])


@pytest.mark.parametrize(
    "model",
    [
        BinarySensorInfo,
        ButtonInfo,
        CoverInfo,
        FanInfo,
        LightInfo,
        NumberInfo,
        DateInfo,
        SelectInfo,
        SensorInfo,
        SirenInfo,
        SwitchInfo,
        TextSensorInfo,
        CameraInfo,
        ClimateInfo,
        LockInfo,
        ValveInfo,
        MediaPlayerInfo,
        AlarmControlPanelInfo,
        TextInfo,
        TimeInfo,
    ],
)
def test_build_unique_id(model):
    obj = model(object_id="id")
    assert build_unique_id("mac", obj) == f"mac-{_TYPE_TO_NAME[type(obj)]}-id"


@pytest.mark.parametrize(
    ("version", "flags"),
    [
        (1, BluetoothProxyFeature.PASSIVE_SCAN),
        (
            2,
            BluetoothProxyFeature.PASSIVE_SCAN
            | BluetoothProxyFeature.ACTIVE_CONNECTIONS,
        ),
        (
            3,
            BluetoothProxyFeature.PASSIVE_SCAN
            | BluetoothProxyFeature.ACTIVE_CONNECTIONS
            | BluetoothProxyFeature.REMOTE_CACHING,
        ),
        (
            4,
            BluetoothProxyFeature.PASSIVE_SCAN
            | BluetoothProxyFeature.ACTIVE_CONNECTIONS
            | BluetoothProxyFeature.REMOTE_CACHING
            | BluetoothProxyFeature.PAIRING,
        ),
        (
            5,
            BluetoothProxyFeature.PASSIVE_SCAN
            | BluetoothProxyFeature.ACTIVE_CONNECTIONS
            | BluetoothProxyFeature.REMOTE_CACHING
            | BluetoothProxyFeature.PAIRING
            | BluetoothProxyFeature.CACHE_CLEARING,
        ),
    ],
)
def test_bluetooth_backcompat_for_device_info(
    version: int, flags: BluetoothProxyFeature
) -> None:
    info = DeviceInfo(
        legacy_bluetooth_proxy_version=version, bluetooth_proxy_feature_flags=42
    )
    assert info.bluetooth_proxy_feature_flags_compat(APIVersion(1, 8)) is flags
    assert info.bluetooth_proxy_feature_flags_compat(APIVersion(1, 9)) == 42


# Add va compat test
@pytest.mark.parametrize(
    ("version", "flags"),
    [
        (1, VoiceAssistantFeature.VOICE_ASSISTANT),
        (2, VoiceAssistantFeature.VOICE_ASSISTANT | VoiceAssistantFeature.SPEAKER),
    ],
)
def test_voice_assistant_backcompat_for_device_info(
    version: int, flags: VoiceAssistantFeature
) -> None:
    info = DeviceInfo(
        legacy_voice_assistant_version=version, voice_assistant_feature_flags=42
    )
    assert info.voice_assistant_feature_flags_compat(APIVersion(1, 9)) is flags
    assert info.voice_assistant_feature_flags_compat(APIVersion(1, 10)) == 42


@pytest.mark.parametrize(
    (
        "legacy_supports_brightness",
        "legacy_supports_rgb",
        "legacy_supports_white_value",
        "legacy_supports_color_temperature",
        "capability",
    ),
    [
        (False, False, False, False, [LightColorCapability.ON_OFF]),
        (
            True,
            False,
            False,
            False,
            [LightColorCapability.ON_OFF | LightColorCapability.BRIGHTNESS],
        ),
        (
            True,
            False,
            False,
            True,
            [
                LightColorCapability.ON_OFF
                | LightColorCapability.BRIGHTNESS
                | LightColorCapability.COLOR_TEMPERATURE
            ],
        ),
        (
            True,
            True,
            False,
            False,
            [
                LightColorCapability.ON_OFF
                | LightColorCapability.BRIGHTNESS
                | LightColorCapability.RGB
            ],
        ),
        (
            True,
            True,
            True,
            False,
            [
                LightColorCapability.ON_OFF
                | LightColorCapability.BRIGHTNESS
                | LightColorCapability.RGB
                | LightColorCapability.WHITE
            ],
        ),
        (
            True,
            True,
            False,
            True,
            [
                LightColorCapability.ON_OFF
                | LightColorCapability.BRIGHTNESS
                | LightColorCapability.RGB
                | LightColorCapability.COLOR_TEMPERATURE
            ],
        ),
        (
            True,
            True,
            True,
            True,
            [
                LightColorCapability.ON_OFF
                | LightColorCapability.BRIGHTNESS
                | LightColorCapability.RGB
                | LightColorCapability.WHITE
                | LightColorCapability.COLOR_TEMPERATURE
            ],
        ),
    ],
)
def test_supported_color_modes_compat(
    legacy_supports_brightness: bool,
    legacy_supports_rgb: bool,
    legacy_supports_white_value: bool,
    legacy_supports_color_temperature: bool,
    capability: list[LightColorCapability],
) -> None:
    info = LightInfo(
        legacy_supports_brightness=legacy_supports_brightness,
        legacy_supports_rgb=legacy_supports_rgb,
        legacy_supports_white_value=legacy_supports_white_value,
        legacy_supports_color_temperature=legacy_supports_color_temperature,
        supported_color_modes=[ColorMode.RGB_COLOR_TEMPERATURE],
    )
    assert info.supported_color_modes_compat(APIVersion(1, 5)) == capability
    assert info.supported_color_modes_compat(APIVersion(1, 9)) == [
        ColorMode.RGB_COLOR_TEMPERATURE
    ]


def test_multiple_supported_color_modes_compat() -> None:
    info = LightInfo(
        supported_color_modes=[ColorMode.RGB_COLOR_TEMPERATURE, ColorMode.RGB],
    )
    assert info.supported_color_modes_compat(APIVersion(1, 9)) == [
        ColorMode.RGB_COLOR_TEMPERATURE,
        ColorMode.RGB,
    ]
    assert info.supported_color_modes == [
        ColorMode.RGB_COLOR_TEMPERATURE,
        ColorMode.RGB,
    ]


def test_legacy_brightness_compat() -> None:
    """Test legacy brightness compatibility."""
    raw_message = (
        b"\x0d\x78\x56\x34\x12"  # key = 0x12345678
        b"\x10\x01"  # state = True
        b"\x1d\xcd\xcc\x4c\x3f"  # brightness = 0.8
        b"\x58\x02"  # color_mode = 2 (LEGACY_BRIGHTNESS)
    )
    msg = LightStateResponse()
    msg.ParseFromString(raw_message)
    assert msg.color_mode == ColorMode.LEGACY_BRIGHTNESS
    assert LightState.from_pb(msg) == LightState(
        key=0x12345678,
        state=True,
        brightness=0.8,
        color_mode=ColorMode.LEGACY_BRIGHTNESS,
    )


async def test_bluetooth_gatt_services_from_dict() -> None:
    """Test bluetooth_gatt_get_services success case."""
    services: message.Message = BluetoothGATTGetServicesResponse(
        address=1234,
        services=[
            {
                "uuid": [1, 1],
                "handle": 1,
                "characteristics": [
                    {
                        "uuid": [1, 2],
                        "handle": 2,
                        "properties": 1,
                        "descriptors": [
                            {"uuid": [1, 3], "handle": 3},
                        ],
                    },
                ],
            }
        ],
    )
    services = BluetoothGATTServicesModel.from_pb(services)
    assert services.services[0] == BluetoothGATTServiceModel(
        uuid=[1, 1],
        handle=1,
        characteristics=[
            BluetoothGATTCharacteristic(
                uuid=[1, 2],
                handle=2,
                properties=1,
                descriptors=[BluetoothGATTDescriptor(uuid=[1, 3], handle=3)],
            )
        ],
    )
    services == BluetoothGATTServicesModel.from_dict(
        {
            "services": [
                {
                    "uuid": [1, 1],
                    "handle": 1,
                    "characteristics": [
                        {
                            "uuid": [1, 2],
                            "handle": 2,
                            "properties": 1,
                            "descriptors": [
                                {"uuid": [1, 3], "handle": 3},
                            ],
                        },
                    ],
                }
            ]
        }
    )
    assert services.services[0] == BluetoothGATTServiceModel(
        uuid=[1, 1],
        handle=1,
        characteristics=[
            BluetoothGATTCharacteristic(
                uuid=[1, 2],
                handle=2,
                properties=1,
                descriptors=[BluetoothGATTDescriptor(uuid=[1, 3], handle=3)],
            )
        ],
    )
    assert BluetoothGATTCharacteristicModel.from_dict(
        {
            "uuid": [1, 2],
            "handle": 2,
            "properties": 1,
            "descriptors": [],
        }
    ) == BluetoothGATTCharacteristicModel(
        uuid=[1, 2],
        handle=2,
        properties=1,
        descriptors=[],
    )
    assert BluetoothGATTDescriptorModel.from_dict(
        {"uuid": [1, 3], "handle": 3},
    ) == BluetoothGATTDescriptorModel(uuid=[1, 3], handle=3)


def test_area_info_convert_list() -> None:
    """Test list conversion for AreaInfo."""
    device_info = DeviceInfo(
        name="Base device",
        areas=[
            AreaInfo(
                area_id=1,
                name="Living Room",
            ),
            AreaInfo(
                area_id=2,
                name="Bedroom",
            ),
        ],
    )
    assert (
        DeviceInfo.from_dict(
            {
                "name": "Base device",
                "areas": [
                    AreaInfoProto(
                        area_id=1,
                        name="Living Room",
                    ),
                    {
                        "area_id": 2,
                        "name": "Bedroom",
                    },
                ],
            }
        )
        == device_info
    )


def test_sub_device_info_convert_list() -> None:
    """Test list conversion for SubDeviceInfo."""
    device_info = DeviceInfo(
        name="Base device",
        devices=[
            SubDeviceInfo(
                device_id=11111111,
                name="Sub dev 1",
                area_id=1,
            ),
            SubDeviceInfo(
                device_id=22222222,
                name="Sub dev 2",
                area_id=2,
            ),
        ],
    )
    assert (
        DeviceInfo.from_dict(
            {
                "name": "Base device",
                "devices": [
                    SubDeviceInfoProto(
                        device_id=11111111,
                        name="Sub dev 1",
                        area_id=1,
                    ),
                    {
                        "device_id": 22222222,
                        "name": "Sub dev 2",
                        "area_id": 2,
                    },
                ],
            }
        )
        == device_info
    )


def test_media_player_supported_format_convert_list() -> None:
    """Test list conversion for MediaPlayerSupportedFormat."""
    assert MediaPlayerInfo.from_dict(
        {
            "supports_pause": False,
            "supported_formats": [
                {
                    "format": "flac",
                    "sample_rate": 48000,
                    "num_channels": 2,
                    "purpose": 1,
                    "sample_bytes": 2,
                }
            ],
        }
    ) == MediaPlayerInfo(
        supports_pause=False,
        supported_formats=[
            MediaPlayerSupportedFormat(
                format="flac",
                sample_rate=48000,
                num_channels=2,
                purpose=1,
                sample_bytes=2,
            )
        ],
    )


def test_device_info_area_field() -> None:
    """Test DeviceInfo with area field set."""
    device_info = DeviceInfo(
        name="Test Device",
        area=AreaInfo(
            area_id=1,
            name="Living Room",
        ),
    )
    assert device_info.area.area_id == 1
    assert device_info.area.name == "Living Room"

    # Test from_pb conversion
    pb_response = DeviceInfoResponse(
        name="Test Device",
        area=AreaInfoProto(
            area_id=2,
            name="Bedroom",
        ),
    )
    device_info_from_pb = DeviceInfo.from_pb(pb_response)
    assert device_info_from_pb.area.area_id == 2
    assert device_info_from_pb.area.name == "Bedroom"


def test_voice_assistant_wake_word_convert_list() -> None:
    """Test list conversion for VoiceAssistantWakeWord."""
    assert VoiceAssistantConfigurationResponse.from_dict(
        {
            "available_wake_words": [
                {
                    "id": 1,
                    "wake_word": "okay nabu",
                    "trained_languages": ["en"],
                }
            ],
            "active_wake_words": ["1234"],
            "max_active_wake_words": 1,
        }
    ) == VoiceAssistantConfigurationResponse(
        available_wake_words=[
            VoiceAssistantWakeWord(
                id=1,
                wake_word="okay nabu",
                trained_languages=["en"],
            )
        ],
        active_wake_words=["1234"],
        max_active_wake_words=1,
    )


def test_device_info_sub_devices_field() -> None:
    """Test DeviceInfo with sub devices field set."""
    device_info = DeviceInfo(
        name="Main Device",
        devices=[
            SubDeviceInfo(
                device_id=11111111,
                name="Sub Device 1",
                area_id=1,
            ),
            SubDeviceInfo(
                device_id=22222222,
                name="Sub Device 2",
                area_id=2,
            ),
        ],
    )
    assert len(device_info.devices) == 2
    assert device_info.devices[0].device_id == 11111111
    assert device_info.devices[0].name == "Sub Device 1"
    assert device_info.devices[0].area_id == 1
    assert device_info.devices[1].device_id == 22222222
    assert device_info.devices[1].name == "Sub Device 2"
    assert device_info.devices[1].area_id == 2

    # Test from_pb conversion
    pb_response = DeviceInfoResponse(
        name="Main Device",
        devices=[
            SubDeviceInfoProto(
                device_id=33333333,
                name="Sub Device 3",
                area_id=3,
            ),
            SubDeviceInfoProto(
                device_id=44444444,
                name="Sub Device 4",
                area_id=4,
            ),
        ],
    )
    device_info_from_pb = DeviceInfo.from_pb(pb_response)
    assert len(device_info_from_pb.devices) == 2
    assert device_info_from_pb.devices[0].device_id == 33333333
    assert device_info_from_pb.devices[0].name == "Sub Device 3"
    assert device_info_from_pb.devices[0].area_id == 3
    assert device_info_from_pb.devices[1].device_id == 44444444
    assert device_info_from_pb.devices[1].name == "Sub Device 4"
    assert device_info_from_pb.devices[1].area_id == 4


def test_entity_info_sub_device_assignment() -> None:
    """Test EntityInfo with device_id field for sub device assignment."""
    # Test that entities can be assigned to sub devices via device_id

    # Test with BinarySensorInfo
    sensor_info = BinarySensorInfo(
        name="Motion Sensor",
        object_id="motion_sensor",
        key=12345,
        device_id=11111111,  # Assigned to sub device 1
        device_class="motion",
    )
    assert sensor_info.device_id == 11111111

    # Test with SwitchInfo
    switch_info = SwitchInfo(
        name="Living Room Light",
        object_id="living_room_light",
        key=23456,
        device_id=22222222,  # Assigned to sub device 2
        assumed_state=False,
    )
    assert switch_info.device_id == 22222222

    # Test from_pb conversion with device_id
    pb_binary_sensor = ListEntitiesBinarySensorResponse(
        name="Temperature Sensor",
        object_id="temp_sensor",
        key=34567,
        device_id=33333333,
        device_class="temperature",
    )
    sensor_from_pb = BinarySensorInfo.from_pb(pb_binary_sensor)
    assert sensor_from_pb.device_id == 33333333
    assert sensor_from_pb.name == "Temperature Sensor"

    # Test from_dict conversion with device_id
    sensor_from_dict = BinarySensorInfo.from_dict(
        {
            "name": "Humidity Sensor",
            "object_id": "humidity_sensor",
            "key": 45678,
            "device_id": 44444444,
            "device_class": "humidity",
        }
    )
    assert sensor_from_dict.device_id == 44444444
    assert sensor_from_dict.name == "Humidity Sensor"


def test_device_info_with_areas_and_sub_devices() -> None:
    """Test DeviceInfo with both areas and sub devices fields for comprehensive conversion testing."""
    # Test complete DeviceInfo structure with areas and sub devices
    device_info = DeviceInfo(
        name="Smart Home Hub",
        friendly_name="My Smart Hub",
        areas=[
            AreaInfo(area_id=1, name="Living Room"),
            AreaInfo(area_id=2, name="Bedroom"),
            AreaInfo(area_id=3, name="Kitchen"),
        ],
        devices=[
            SubDeviceInfo(device_id=11111111, name="Motion Sensor", area_id=1),
            SubDeviceInfo(device_id=22222222, name="Light Switch", area_id=1),
            SubDeviceInfo(device_id=33333333, name="Temperature Sensor", area_id=2),
        ],
        area=AreaInfo(area_id=0, name="Main Hub"),
    )

    # Test to_dict conversion
    device_dict = device_info.to_dict()
    assert device_dict["name"] == "Smart Home Hub"
    assert len(device_dict["areas"]) == 3
    assert len(device_dict["devices"]) == 3
    assert device_dict["area"]["name"] == "Main Hub"

    # Test from_dict conversion with mixed proto and dict objects
    device_from_mixed = DeviceInfo.from_dict(
        {
            "name": "Smart Home Hub 2",
            "areas": [
                AreaInfoProto(area_id=4, name="Garage"),
                {"area_id": 5, "name": "Basement"},
            ],
            "devices": [
                SubDeviceInfoProto(device_id=44444444, name="Door Sensor", area_id=4),
                {"device_id": 55555555, "name": "Leak Detector", "area_id": 5},
            ],
        }
    )
    assert device_from_mixed.name == "Smart Home Hub 2"
    assert len(device_from_mixed.areas) == 2
    assert device_from_mixed.areas[0].area_id == 4
    assert device_from_mixed.areas[0].name == "Garage"
    assert device_from_mixed.areas[1].area_id == 5
    assert device_from_mixed.areas[1].name == "Basement"
    assert len(device_from_mixed.devices) == 2
    assert device_from_mixed.devices[0].device_id == 44444444
    assert device_from_mixed.devices[0].name == "Door Sensor"
    assert device_from_mixed.devices[1].device_id == 55555555
    assert device_from_mixed.devices[1].name == "Leak Detector"


def test_device_info_mock_with_friendly_name() -> None:
    """Test that mocking DeviceInfo with friendly_name works after areas/devices were added."""
    # Create a device info object
    device = DeviceInfo(name="Test Device", friendly_name="Original Friendly Name")

    # Try to mock it by modifying the friendly_name field like the user's example
    # This simulates what a user would do when mocking
    mocked_device = DeviceInfo(
        **{**device.to_dict(), "friendly_name": "I have a friendly name"}
    )

    # This should work and the friendly_name should be updated
    assert mocked_device.friendly_name == "I have a friendly name"
    assert mocked_device.name == "Test Device"  # Other fields should be preserved


def test_device_info_mock_with_areas_and_devices() -> None:
    """Test that mocking DeviceInfo with areas and devices works correctly."""
    # Create a device info object with areas and devices
    device = DeviceInfo(
        name="Test Device",
        friendly_name="Original Friendly Name",
        areas=[
            AreaInfo(area_id=1, name="Living Room"),
            AreaInfo(area_id=2, name="Bedroom"),
        ],
        devices=[
            SubDeviceInfo(device_id=100, name="Sub Device 1", area_id=1),
            SubDeviceInfo(device_id=200, name="Sub Device 2", area_id=2),
        ],
        area=AreaInfo(area_id=0, name="Main Area"),
    )

    # Convert to dict and back to simulate mocking
    device_dict = device.to_dict()

    # Modify some fields
    device_dict["friendly_name"] = "Modified Friendly Name"
    device_dict["area"]["name"] = "Modified Main Area"
    device_dict["areas"][0]["name"] = "Modified Living Room"
    device_dict["devices"][1]["name"] = "Modified Sub Device 2"

    # Create a new DeviceInfo from the modified dict
    mocked_device = DeviceInfo(**device_dict)

    # Verify all fields are correctly handled
    assert mocked_device.name == "Test Device"
    assert mocked_device.friendly_name == "Modified Friendly Name"

    # Check area field
    assert mocked_device.area.area_id == 0
    assert mocked_device.area.name == "Modified Main Area"

    # Check areas list
    assert len(mocked_device.areas) == 2
    assert mocked_device.areas[0].area_id == 1
    assert mocked_device.areas[0].name == "Modified Living Room"
    assert mocked_device.areas[1].area_id == 2
    assert mocked_device.areas[1].name == "Bedroom"

    # Check devices list
    assert len(mocked_device.devices) == 2
    assert mocked_device.devices[0].device_id == 100
    assert mocked_device.devices[0].name == "Sub Device 1"
    assert mocked_device.devices[0].area_id == 1
    assert mocked_device.devices[1].device_id == 200
    assert mocked_device.devices[1].name == "Modified Sub Device 2"


# ==================== DEVICE_ID TESTS ====================

# Test data for all state response types with device_id field
STATE_RESPONSE_DEVICE_ID_TEST_DATA = [
    # (protobuf_class, model_class, extra_fields)
    (BinarySensorStateResponse, BinarySensorState, {"state": True}),
    (CoverStateResponse, CoverState, {"position": 0.5}),
    (FanStateResponse, FanState, {"state": True, "speed_level": 3}),
    (LightStateResponse, LightState, {"state": True, "brightness": 0.8}),
    (SensorStateResponse, SensorState, {"state": 25.5}),
    (SwitchStateResponse, SwitchState, {"state": True}),
    (TextSensorStateResponse, TextSensorState, {"state": "test"}),
    (ClimateStateResponse, ClimateState, {"mode": 1, "current_temperature": 22.0}),
    (NumberStateResponse, NumberState, {"state": 42.0}),
    (SelectStateResponse, SelectState, {"state": "option1"}),
    (SirenStateResponse, SirenState, {"state": True}),
    (LockStateResponse, LockEntityState, {"state": 1}),
    (MediaPlayerStateResponse, MediaPlayerEntityState, {"state": 2, "volume": 0.5}),
    (AlarmControlPanelStateResponse, AlarmControlPanelEntityState, {"state": 1}),
    (TextStateResponse, TextState, {"state": "text"}),
    (DateStateResponse, DateState, {"year": 2024, "month": 1, "day": 15}),
    (TimeStateResponse, TimeState, {"hour": 12, "minute": 30, "second": 0}),
    (EventResponse, Event, {"event_type": "button_press"}),
    (ValveStateResponse, ValveState, {"position": 0.75}),
    (DateTimeStateResponse, DateTimeState, {"epoch_seconds": 1737000000}),
    (UpdateStateResponse, UpdateState, {"current_version": "1.0.0"}),
]


@pytest.mark.parametrize(
    ("proto_cls", "model_cls", "extra_fields"), STATE_RESPONSE_DEVICE_ID_TEST_DATA
)
def test_state_response_has_device_id_field(proto_cls, model_cls, extra_fields):
    """Test that all StateResponse protobuf messages have device_id field."""
    # Create protobuf message with device_id
    proto_msg = proto_cls(key=123, device_id=456, **extra_fields)

    # Verify the protobuf message has the device_id field set
    assert proto_msg.key == 123
    assert proto_msg.device_id == 456

    # Convert to model and verify device_id is preserved
    model_instance = model_cls.from_pb(proto_msg)
    assert model_instance.key == 123
    assert model_instance.device_id == 456


@pytest.mark.parametrize(
    ("proto_cls", "model_cls", "extra_fields"), STATE_RESPONSE_DEVICE_ID_TEST_DATA
)
def test_state_response_device_id_default_value(proto_cls, model_cls, extra_fields):
    """Test that device_id defaults to 0 when not set."""
    # Create protobuf message without device_id
    proto_msg = proto_cls(key=123, **extra_fields)

    # Verify default value is 0
    assert proto_msg.device_id == 0

    # Convert to model and verify default
    model_instance = model_cls.from_pb(proto_msg)
    assert model_instance.device_id == 0


def test_entity_state_base_class_has_device_id():
    """Test that EntityState base class has device_id field."""

    # Check that EntityState has device_id field with default value 0
    state = EntityState(key=100)
    assert state.key == 100
    assert state.device_id == 0

    # Check that device_id can be set
    state_with_device = EntityState(key=100, device_id=42)
    assert state_with_device.key == 100
    assert state_with_device.device_id == 42


def test_state_model_to_dict_includes_device_id():
    """Test that to_dict() includes device_id field."""
    # Test a few different state types
    sensor_state = SensorState(key=1, state=25.5, device_id=10)
    sensor_dict = sensor_state.to_dict()
    assert sensor_dict["key"] == 1
    assert sensor_dict["state"] == 25.5
    assert sensor_dict["device_id"] == 10

    switch_state = SwitchState(key=2, state=True, device_id=20)
    switch_dict = switch_state.to_dict()
    assert switch_dict["key"] == 2
    assert switch_dict["state"] is True
    assert switch_dict["device_id"] == 20


def test_state_model_from_dict_handles_device_id():
    """Test that from_dict() properly handles device_id field."""
    # Test creating from dict with device_id
    sensor_dict = {"key": 1, "state": 25.5, "device_id": 10, "missing_state": False}
    sensor_state = SensorState.from_dict(sensor_dict)
    assert sensor_state.key == 1
    assert sensor_state.state == 25.5
    assert sensor_state.device_id == 10

    # Test creating from dict without device_id (should default to 0)
    switch_dict = {"key": 2, "state": True}
    switch_state = SwitchState.from_dict(switch_dict)
    assert switch_state.key == 2
    assert switch_state.state is True
    assert switch_state.device_id == 0


def test_event_entity_state_device_id():
    """Test Event entity state specifically for device_id handling."""
    # Test Event with device_id set
    event_proto = EventResponse(key=100, event_type="button_press", device_id=42)
    assert event_proto.key == 100
    assert event_proto.event_type == "button_press"
    assert event_proto.device_id == 42

    # Convert to model
    event_model = Event.from_pb(event_proto)
    assert event_model.key == 100
    assert event_model.event_type == "button_press"
    assert event_model.device_id == 42

    # Test Event without device_id (defaults to 0)
    event_proto_no_device = EventResponse(key=101, event_type="motion_detected")
    assert event_proto_no_device.device_id == 0

    event_model_no_device = Event.from_pb(event_proto_no_device)
    assert event_model_no_device.key == 101
    assert event_model_no_device.event_type == "motion_detected"
    assert event_model_no_device.device_id == 0

    # Test to_dict includes device_id
    event_dict = event_model.to_dict()
    assert event_dict == {"key": 100, "event_type": "button_press", "device_id": 42}

    # Test from_dict with device_id
    event_from_dict = Event.from_dict(
        {"key": 102, "event_type": "door_opened", "device_id": 99}
    )
    assert event_from_dict.key == 102
    assert event_from_dict.event_type == "door_opened"
    assert event_from_dict.device_id == 99
