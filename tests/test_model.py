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
    BluetoothGATTService as BluetoothGATTServicePb,
    BluetoothScannerStateResponse,
    ClimateStateResponse,
    CoverStateResponse,
    DateStateResponse,
    DateTimeStateResponse,
    DeviceInfo as SubDeviceInfoProto,
    DeviceInfoResponse,
    EventResponse,
    ExecuteServiceResponse as ExecuteServiceResponsePb,
    FanStateResponse,
    HomeassistantActionRequest,
    HomeassistantServiceMap,
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
    ListEntitiesWaterHeaterResponse,
    LockStateResponse,
    MediaPlayerStateResponse,
    MediaPlayerSupportedFormat,
    NoiseEncryptionSetKeyResponse,
    NumberStateResponse,
    SelectStateResponse,
    SensorStateResponse,
    ServiceArgType,
    SirenStateResponse,
    SupportsResponseType as SupportsResponseTypePb,
    SwitchStateResponse,
    TextSensorStateResponse,
    TextStateResponse,
    TimeStateResponse,
    UpdateStateResponse,
    ValveStateResponse,
    WaterHeaterStateResponse,
    ZWaveProxyFrame as ZWaveProxyFramePb,
    ZWaveProxyRequest as ZWaveProxyRequestPb,
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
    ClimateFeature,
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
    ExecuteServiceResponse,
    FanInfo,
    FanState,
    HomeassistantServiceCall,
    LegacyCoverState,
    LightColorCapability,
    LightInfo,
    LightState,
    LockEntityState,
    LockInfo,
    MediaPlayerEntityFeature,
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
    SupportsResponseType,
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
    WaterHeaterInfo,
    WaterHeaterState,
    ZWaveProxyFeature,
    ZWaveProxyFrame,
    ZWaveProxyRequest,
    ZWaveProxyRequestType,
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
        (HomeassistantServiceCall, HomeassistantActionRequest),
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
        (ZWaveProxyFrame, ZWaveProxyFramePb),
        (ZWaveProxyRequest, ZWaveProxyRequestPb),
        (ExecuteServiceResponse, ExecuteServiceResponsePb),
        (WaterHeaterInfo, ListEntitiesWaterHeaterResponse),
        (WaterHeaterState, WaterHeaterStateResponse),
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
        (
            ClimateInfo(supports_current_temperature=True),
            (1, 12),
            ClimateFeature.SUPPORTS_CURRENT_TEMPERATURE,
        ),
        (
            ClimateInfo(supports_two_point_target_temperature=True),
            (1, 12),
            ClimateFeature.REQUIRES_TWO_POINT_TARGET_TEMPERATURE,
        ),
        (
            ClimateInfo(supports_current_humidity=True),
            (1, 12),
            ClimateFeature.SUPPORTS_CURRENT_HUMIDITY,
        ),
        (
            ClimateInfo(supports_target_humidity=True),
            (1, 12),
            ClimateFeature.SUPPORTS_TARGET_HUMIDITY,
        ),
        (ClimateInfo(supports_action=True), (1, 12), ClimateFeature.SUPPORTS_ACTION),
        (
            ClimateInfo(
                feature_flags=ClimateFeature.SUPPORTS_CURRENT_TEMPERATURE
                | ClimateFeature.SUPPORTS_ACTION
            ),
            (1, 13),
            ClimateFeature.SUPPORTS_CURRENT_TEMPERATURE
            | ClimateFeature.SUPPORTS_ACTION,
        ),
    ],
)
def test_climate_info_supported_feature_flags_compat(state, version, out):
    assert state.supported_feature_flags_compat(APIVersion(*version)) == out


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
        HomeassistantActionRequest(
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
        WaterHeaterInfo,
    ],
)
def test_build_unique_id(model):
    obj = model(object_id="id", name="My Sensor")
    # Version 1 (default): uses object_id
    assert build_unique_id("mac", obj) == f"mac-{_TYPE_TO_NAME[type(obj)]}-id"
    assert (
        build_unique_id("mac", obj, version=1) == f"mac-{_TYPE_TO_NAME[type(obj)]}-id"
    )
    # Version 2: uses name directly (preserves spaces, Unicode, etc.)
    assert (
        build_unique_id("mac", obj, version=2)
        == f"mac-{_TYPE_TO_NAME[type(obj)]}-My Sensor"
    )


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
    ("flags", "home_id"),
    [
        (ZWaveProxyFeature.ENABLED, 0x12345678),
        (0, 0x01234567),
    ],
)
def test_zwave_backcompat_for_device_info(
    flags: ZWaveProxyFeature, home_id: int
) -> None:
    info = DeviceInfo(zwave_proxy_feature_flags=flags, zwave_home_id=home_id)
    assert info.zwave_proxy_feature_flags_compat(APIVersion(1, 9)) == flags
    assert info.zwave_home_id == home_id


def test_zwave_proxy_frame_conversion() -> None:
    """Test ZWaveProxyFrame conversion from protobuf."""
    # Test with empty data
    pb_frame = ZWaveProxyFramePb()
    frame = ZWaveProxyFrame.from_pb(pb_frame)
    assert frame.data == b""

    # Test with actual data
    pb_frame_with_data = ZWaveProxyFramePb(data=b"\x01\x02\x03\x04")
    frame_with_data = ZWaveProxyFrame.from_pb(pb_frame_with_data)
    assert frame_with_data.data == b"\x01\x02\x03\x04"

    # Test to_dict
    assert frame_with_data.to_dict() == {"data": b"\x01\x02\x03\x04"}

    # Test from_dict
    frame_from_dict = ZWaveProxyFrame.from_dict({"data": b"\x05\x06\x07\x08"})
    assert frame_from_dict.data == b"\x05\x06\x07\x08"


def test_zwave_proxy_request_type_enum() -> None:
    """Test ZWaveProxyRequestType enum values."""
    assert ZWaveProxyRequestType.SUBSCRIBE == 0
    assert ZWaveProxyRequestType.UNSUBSCRIBE == 1
    assert ZWaveProxyRequestType.HOME_ID_CHANGE == 2

    # Test conversion
    assert ZWaveProxyRequestType.convert(0) == ZWaveProxyRequestType.SUBSCRIBE
    assert ZWaveProxyRequestType.convert(1) == ZWaveProxyRequestType.UNSUBSCRIBE
    assert ZWaveProxyRequestType.convert(2) == ZWaveProxyRequestType.HOME_ID_CHANGE
    assert ZWaveProxyRequestType.convert(3) is None
    assert ZWaveProxyRequestType.convert(-1) is None


def test_zwave_proxy_request_conversion() -> None:
    """Test ZWaveProxyRequest conversion from protobuf."""
    # Test with default value (SUBSCRIBE)
    pb_request = ZWaveProxyRequestPb()
    request = ZWaveProxyRequest.from_pb(pb_request)
    assert request.type == ZWaveProxyRequestType.SUBSCRIBE

    # Test with UNSUBSCRIBE
    pb_request_unsub = ZWaveProxyRequestPb(type=1)
    request_unsub = ZWaveProxyRequest.from_pb(pb_request_unsub)
    assert request_unsub.type == ZWaveProxyRequestType.UNSUBSCRIBE

    # Test with HOME_ID_CHANGE
    pb_request_home_id_change = ZWaveProxyRequestPb(type=2, data=b"1,2,3,4")
    request_home_id_change = ZWaveProxyRequest.from_pb(pb_request_home_id_change)
    assert request_home_id_change.type == ZWaveProxyRequestType.HOME_ID_CHANGE

    # Test to_dict
    assert request.to_dict() == {"type": 0, "data": b""}
    assert request_unsub.to_dict() == {"type": 1, "data": b""}
    assert request_home_id_change.to_dict() == {"type": 2, "data": b"1,2,3,4"}

    # Test from_dict
    request_from_dict = ZWaveProxyRequest.from_dict({"type": 1})
    assert request_from_dict.type == ZWaveProxyRequestType.UNSUBSCRIBE

    # Test from_dict with default when not provided
    request_default = ZWaveProxyRequest.from_dict({})
    assert request_default.type == ZWaveProxyRequestType.SUBSCRIBE


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
        uuid="00000000-0000-0001-0000-000000000001",
        handle=1,
        characteristics=[
            BluetoothGATTCharacteristicModel(
                uuid="00000000-0000-0001-0000-000000000002",
                handle=2,
                properties=1,
                descriptors=[
                    BluetoothGATTDescriptorModel(
                        uuid="00000000-0000-0001-0000-000000000003", handle=3
                    )
                ],
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
        uuid="00000000-0000-0001-0000-000000000001",
        handle=1,
        characteristics=[
            BluetoothGATTCharacteristicModel(
                uuid="00000000-0000-0001-0000-000000000002",
                handle=2,
                properties=1,
                descriptors=[
                    BluetoothGATTDescriptorModel(
                        uuid="00000000-0000-0001-0000-000000000003", handle=3
                    )
                ],
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
        uuid="00000000-0000-0001-0000-000000000002",
        handle=2,
        properties=1,
        descriptors=[],
    )
    assert BluetoothGATTDescriptorModel.from_dict(
        {"uuid": [1, 3], "handle": 3},
    ) == BluetoothGATTDescriptorModel(
        uuid="00000000-0000-0001-0000-000000000003", handle=3
    )


def test_bluetooth_16bit_uuid_conversion() -> None:
    """Test conversion of 16-bit UUIDs."""
    # Create a descriptor with a 16-bit UUID
    pb_descriptor = BluetoothGATTDescriptor()
    pb_descriptor.short_uuid = 0x2902  # Client Characteristic Configuration
    pb_descriptor.handle = 42

    descriptor = BluetoothGATTDescriptorModel.from_pb(pb_descriptor)
    assert descriptor.uuid == "00002902-0000-1000-8000-00805f9b34fb"
    assert descriptor.handle == 42


def test_bluetooth_32bit_uuid_conversion() -> None:
    """Test conversion of 32-bit UUIDs."""
    # Create a descriptor with a 32-bit UUID
    pb_descriptor = BluetoothGATTDescriptor()
    pb_descriptor.short_uuid = 0x12345678
    pb_descriptor.handle = 43

    descriptor = BluetoothGATTDescriptorModel.from_pb(pb_descriptor)
    assert descriptor.uuid == "12345678-0000-1000-8000-00805f9b34fb"
    assert descriptor.handle == 43


def test_bluetooth_128bit_uuid_fallback() -> None:
    """Test fallback to 128-bit UUID when no efficient UUID is present."""
    # Create a descriptor with only 128-bit UUID
    pb_descriptor = BluetoothGATTDescriptor()
    pb_descriptor.uuid.extend([0x123456789ABCDEF0, 0x1122334455667788])
    pb_descriptor.handle = 44

    descriptor = BluetoothGATTDescriptorModel.from_pb(pb_descriptor)
    assert descriptor.uuid == "12345678-9abc-def0-1122-334455667788"
    assert descriptor.handle == 44


def test_bluetooth_characteristic_efficient_uuids() -> None:
    """Test characteristic with mixed UUID types in descriptors."""
    pb_char = BluetoothGATTCharacteristic()
    pb_char.short_uuid = 0x2A00  # Device Name
    pb_char.handle = 10
    pb_char.properties = 0x02  # Read

    # Add descriptors with different UUID types
    desc1 = pb_char.descriptors.add()
    desc1.short_uuid = 0x2901  # Characteristic User Description
    desc1.handle = 11

    desc2 = pb_char.descriptors.add()
    desc2.short_uuid = 0xABCDEF00
    desc2.handle = 12

    characteristic = BluetoothGATTCharacteristicModel.from_pb(pb_char)
    assert characteristic.uuid == "00002a00-0000-1000-8000-00805f9b34fb"
    assert characteristic.handle == 10
    assert characteristic.properties == 0x02
    assert len(characteristic.descriptors) == 2
    assert characteristic.descriptors[0].uuid == "00002901-0000-1000-8000-00805f9b34fb"
    assert characteristic.descriptors[1].uuid == "abcdef00-0000-1000-8000-00805f9b34fb"


def test_bluetooth_service_efficient_uuids() -> None:
    """Test service with efficient UUIDs throughout."""
    pb_service = BluetoothGATTServicePb()
    pb_service.short_uuid = 0x180A  # Device Information Service
    pb_service.handle = 1

    # Add characteristic
    char = pb_service.characteristics.add()
    char.short_uuid = 0x2A29  # Manufacturer Name String
    char.handle = 2
    char.properties = 0x02

    service = BluetoothGATTServiceModel.from_pb(pb_service)
    assert service.uuid == "0000180a-0000-1000-8000-00805f9b34fb"
    assert service.handle == 1
    assert len(service.characteristics) == 1
    assert service.characteristics[0].uuid == "00002a29-0000-1000-8000-00805f9b34fb"


def test_bluetooth_uuid_priority() -> None:
    """Test that efficient UUID fields take priority over 128-bit."""
    # If both short_uuid and 128-bit are present, short_uuid should be used
    pb_descriptor = BluetoothGATTDescriptor()
    pb_descriptor.short_uuid = 0x2902
    pb_descriptor.uuid.extend([0x123456789ABCDEF0, 0x1122334455667788])
    pb_descriptor.handle = 45

    descriptor = BluetoothGATTDescriptorModel.from_pb(pb_descriptor)
    # Should use the short_uuid, not the 128-bit
    assert descriptor.uuid == "00002902-0000-1000-8000-00805f9b34fb"


def test_bluetooth_gatt_nested_structure() -> None:
    """Test nested GATT structure with all efficient UUID types."""
    # Create a complete service with characteristics and descriptors
    pb_service = BluetoothGATTServicePb()
    pb_service.short_uuid = 0x180D  # Heart Rate Service
    pb_service.handle = 10

    # First characteristic - Heart Rate Measurement (16-bit UUID)
    char1 = pb_service.characteristics.add()
    char1.short_uuid = 0x2A37  # Heart Rate Measurement
    char1.handle = 11
    char1.properties = 0x10  # Notify

    # Add descriptor to first characteristic (16-bit UUID)
    desc1 = char1.descriptors.add()
    desc1.short_uuid = 0x2902  # Client Characteristic Configuration
    desc1.handle = 12

    # Second characteristic - Body Sensor Location (32-bit UUID)
    char2 = pb_service.characteristics.add()
    char2.short_uuid = 0x12345678  # Custom 32-bit UUID
    char2.handle = 13
    char2.properties = 0x02  # Read

    # Add descriptor to second characteristic (128-bit UUID)
    desc2 = char2.descriptors.add()
    desc2.uuid.extend([0x123456789ABCDEF0, 0x1122334455667788])
    desc2.handle = 14

    # Convert to model
    service = BluetoothGATTServiceModel.from_pb(pb_service)

    # Verify service
    assert service.uuid == "0000180d-0000-1000-8000-00805f9b34fb"
    assert service.handle == 10
    assert len(service.characteristics) == 2

    # Verify first characteristic
    assert service.characteristics[0].uuid == "00002a37-0000-1000-8000-00805f9b34fb"
    assert service.characteristics[0].handle == 11
    assert service.characteristics[0].properties == 0x10
    assert len(service.characteristics[0].descriptors) == 1
    assert (
        service.characteristics[0].descriptors[0].uuid
        == "00002902-0000-1000-8000-00805f9b34fb"
    )
    assert service.characteristics[0].descriptors[0].handle == 12

    # Verify second characteristic
    assert service.characteristics[1].uuid == "12345678-0000-1000-8000-00805f9b34fb"
    assert service.characteristics[1].handle == 13
    assert service.characteristics[1].properties == 0x02
    assert len(service.characteristics[1].descriptors) == 1
    assert (
        service.characteristics[1].descriptors[0].uuid
        == "12345678-9abc-def0-1122-334455667788"
    )
    assert service.characteristics[1].descriptors[0].handle == 14


def test_bluetooth_gatt_services_response_efficient_uuids() -> None:
    """Test BluetoothGATTGetServicesResponse with multiple services using efficient UUIDs."""
    # Create response with multiple services
    pb_response = BluetoothGATTGetServicesResponse()
    pb_response.address = 0x112233445566

    # First service - Generic Access (16-bit UUID)
    service1 = pb_response.services.add()
    service1.short_uuid = 0x1800  # Generic Access
    service1.handle = 1

    # Add characteristic to first service
    char1 = service1.characteristics.add()
    char1.short_uuid = 0x2A00  # Device Name
    char1.handle = 2
    char1.properties = 0x02  # Read

    # Second service - Battery Service (32-bit UUID)
    service2 = pb_response.services.add()
    service2.short_uuid = 0xABCDEF00  # Custom service
    service2.handle = 10

    # Add characteristic with descriptor
    char2 = service2.characteristics.add()
    char2.short_uuid = 0x2A19  # Battery Level
    char2.handle = 11
    char2.properties = 0x12  # Read | Notify

    desc = char2.descriptors.add()
    desc.short_uuid = 0x2902  # Client Characteristic Configuration
    desc.handle = 12

    # Third service - Custom Service (128-bit UUID)
    service3 = pb_response.services.add()
    service3.uuid.extend([0x123456789ABCDEF0, 0xFEDCBA9876543210])
    service3.handle = 20

    # Convert to model
    services_model = BluetoothGATTServicesModel.from_pb(pb_response)

    # Verify response
    assert services_model.address == 0x112233445566
    assert len(services_model.services) == 3

    # Verify first service
    assert services_model.services[0].uuid == "00001800-0000-1000-8000-00805f9b34fb"
    assert services_model.services[0].handle == 1
    assert len(services_model.services[0].characteristics) == 1
    assert (
        services_model.services[0].characteristics[0].uuid
        == "00002a00-0000-1000-8000-00805f9b34fb"
    )

    # Verify second service
    assert services_model.services[1].uuid == "abcdef00-0000-1000-8000-00805f9b34fb"
    assert services_model.services[1].handle == 10
    assert len(services_model.services[1].characteristics) == 1
    assert (
        services_model.services[1].characteristics[0].uuid
        == "00002a19-0000-1000-8000-00805f9b34fb"
    )
    assert len(services_model.services[1].characteristics[0].descriptors) == 1
    assert (
        services_model.services[1].characteristics[0].descriptors[0].uuid
        == "00002902-0000-1000-8000-00805f9b34fb"
    )

    # Verify third service
    assert services_model.services[2].uuid == "12345678-9abc-def0-fedc-ba9876543210"
    assert services_model.services[2].handle == 20


def test_bluetooth_gatt_old_format_compatibility() -> None:
    """Test compatibility with old ESPHome versions that only send 128-bit UUIDs."""
    # Create response as old ESPHome would send (only 128-bit UUIDs)
    pb_response = BluetoothGATTGetServicesResponse()
    pb_response.address = 0x112233445566

    # Service with only 128-bit UUID (old format)
    service = pb_response.services.add()
    # 0x1800 = Generic Access Service as 128-bit
    # UUID: 00001800-0000-1000-8000-00805F9B34FB
    service.uuid.extend([0x0000180000001000, 0x800000805F9B34FB])
    service.handle = 1

    # Characteristic with only 128-bit UUID
    char = service.characteristics.add()
    # 0x2A00 = Device Name as 128-bit
    # UUID: 00002A00-0000-1000-8000-00805F9B34FB
    char.uuid.extend([0x00002A0000001000, 0x800000805F9B34FB])
    char.handle = 2
    char.properties = 0x02

    # Descriptor with only 128-bit UUID
    desc = char.descriptors.add()
    # 0x2902 = Client Characteristic Configuration as 128-bit
    # UUID: 00002902-0000-1000-8000-00805F9B34FB
    desc.uuid.extend([0x0000290200001000, 0x800000805F9B34FB])
    desc.handle = 3

    # Convert to model
    services_model = BluetoothGATTServicesModel.from_pb(pb_response)

    # Verify all UUIDs are correctly converted from 128-bit format
    assert services_model.address == 0x112233445566
    assert len(services_model.services) == 1

    # Service UUID should be properly formatted
    assert services_model.services[0].uuid == "00001800-0000-1000-8000-00805f9b34fb"
    assert services_model.services[0].handle == 1

    # Characteristic UUID
    assert len(services_model.services[0].characteristics) == 1
    assert (
        services_model.services[0].characteristics[0].uuid
        == "00002a00-0000-1000-8000-00805f9b34fb"
    )
    assert services_model.services[0].characteristics[0].handle == 2

    # Descriptor UUID
    assert len(services_model.services[0].characteristics[0].descriptors) == 1
    assert (
        services_model.services[0].characteristics[0].descriptors[0].uuid
        == "00002902-0000-1000-8000-00805f9b34fb"
    )
    assert services_model.services[0].characteristics[0].descriptors[0].handle == 3


def test_bluetooth_gatt_mixed_format() -> None:
    """Test handling mixed UUID formats in the same response."""
    # This simulates a scenario where some UUIDs use efficient format and others don't
    pb_response = BluetoothGATTGetServicesResponse()
    pb_response.address = 0xAABBCCDDEEFF

    # Service 1: Uses efficient 16-bit UUID
    service1 = pb_response.services.add()
    service1.short_uuid = 0x180F  # Battery Service
    service1.handle = 10

    # Characteristic with old 128-bit format
    char1 = service1.characteristics.add()
    char1.uuid.extend([0x00002A1900001000, 0x800000805F9B34FB])  # Battery Level
    char1.handle = 11
    char1.properties = 0x12

    # Service 2: Uses old 128-bit format
    service2 = pb_response.services.add()
    service2.uuid.extend([0x0000180A00001000, 0x800000805F9B34FB])  # Device Information
    service2.handle = 20

    # Characteristic with efficient 32-bit format
    char2 = service2.characteristics.add()
    char2.short_uuid = 0x12345678
    char2.handle = 21
    char2.properties = 0x02

    # Convert to model
    services_model = BluetoothGATTServicesModel.from_pb(pb_response)

    # Verify mixed format handling
    assert len(services_model.services) == 2

    # Service 1 uses efficient format
    assert services_model.services[0].uuid == "0000180f-0000-1000-8000-00805f9b34fb"
    # Its characteristic uses old format
    assert (
        services_model.services[0].characteristics[0].uuid
        == "00002a19-0000-1000-8000-00805f9b34fb"
    )

    # Service 2 uses old format
    assert services_model.services[1].uuid == "0000180a-0000-1000-8000-00805f9b34fb"
    # Its characteristic uses efficient format
    assert (
        services_model.services[1].characteristics[0].uuid
        == "12345678-0000-1000-8000-00805f9b34fb"
    )


def test_bluetooth_gatt_from_pb_already_model() -> None:
    """Test from_pb methods when data is already a model instance."""
    # Test BluetoothGATTDescriptor
    descriptor = BluetoothGATTDescriptorModel(
        uuid="00002902-0000-1000-8000-00805f9b34fb", handle=10
    )
    result = BluetoothGATTDescriptorModel.from_pb(descriptor)
    assert result is descriptor  # Should return the same instance

    # Test BluetoothGATTCharacteristic
    characteristic = BluetoothGATTCharacteristicModel(
        uuid="00002a00-0000-1000-8000-00805f9b34fb",
        handle=20,
        properties=0x02,
        descriptors=[descriptor],
    )
    result = BluetoothGATTCharacteristicModel.from_pb(characteristic)
    assert result is characteristic  # Should return the same instance

    # Test BluetoothGATTService
    service = BluetoothGATTServiceModel(
        uuid="00001800-0000-1000-8000-00805f9b34fb",
        handle=30,
        characteristics=[characteristic],
    )
    result = BluetoothGATTServiceModel.from_pb(service)
    assert result is service  # Should return the same instance


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
            "feature_flags": 0,
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
        feature_flags=0,
    )


def test_media_player_feature_flags_compat() -> None:
    """Test feature flags compatibility across API versions"""
    info = MediaPlayerInfo(
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
        feature_flags=999999,  # Different from calculated compatibility flags
    )
    # For API version < 1.11, should return calculated compatibility flags
    compat_flags = info.feature_flags_compat(APIVersion(1, 10))
    expected_compat = (
        MediaPlayerEntityFeature.PLAY_MEDIA
        | MediaPlayerEntityFeature.BROWSE_MEDIA
        | MediaPlayerEntityFeature.STOP
        | MediaPlayerEntityFeature.VOLUME_SET
        | MediaPlayerEntityFeature.VOLUME_MUTE
        | MediaPlayerEntityFeature.MEDIA_ANNOUNCE
    )
    assert compat_flags == expected_compat

    # For API version >= 1.11, should return feature_flags directly
    direct_flags = info.feature_flags_compat(APIVersion(1, 11))
    assert direct_flags == 999999

    # Test with supports_pause=True to verify PAUSE|PLAY flags are added
    info_with_pause = MediaPlayerInfo(supports_pause=True, feature_flags=888888)
    compat_with_pause = info_with_pause.feature_flags_compat(APIVersion(1, 10))
    expected_with_pause = (
        expected_compat | MediaPlayerEntityFeature.PAUSE | MediaPlayerEntityFeature.PLAY
    )
    assert compat_with_pause == expected_with_pause


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
    (WaterHeaterStateResponse, WaterHeaterState, {"current_temperature": 60.0}),
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


@pytest.mark.parametrize(
    "input, output",
    [
        (0, SupportsResponseType.NONE),
        (1, SupportsResponseType.OPTIONAL),
        (2, SupportsResponseType.ONLY),
        (100, SupportsResponseType.STATUS),
        (999, None),  # Unknown value
    ],
)
def test_supports_response_type_convert(input, output):
    assert SupportsResponseType.convert(input) == output


def test_supports_response_type_values():
    """Test that SupportsResponseType enum has expected values."""
    assert SupportsResponseType.NONE == 0
    assert SupportsResponseType.OPTIONAL == 1
    assert SupportsResponseType.ONLY == 2
    assert SupportsResponseType.STATUS == 100


def test_user_service_with_supports_response():
    """Test UserService model with supports_response field."""
    # Test from protobuf with supports_response
    pb = ListEntitiesServicesResponse(
        name="test_service",
        key=123,
        supports_response=SupportsResponseTypePb.SUPPORTS_RESPONSE_OPTIONAL,
    )
    service = UserService.from_pb(pb)
    assert service.name == "test_service"
    assert service.key == 123
    assert service.supports_response == SupportsResponseType.OPTIONAL
    assert service.args == []

    # Test with STATUS response type
    pb_status = ListEntitiesServicesResponse(
        name="status_service",
        key=456,
        supports_response=SupportsResponseTypePb.SUPPORTS_RESPONSE_STATUS,
    )
    service_status = UserService.from_pb(pb_status)
    assert service_status.supports_response == SupportsResponseType.STATUS

    # Test default value (NONE)
    pb_default = ListEntitiesServicesResponse(name="default_service", key=789)
    service_default = UserService.from_pb(pb_default)
    assert service_default.supports_response == SupportsResponseType.NONE

    # Test from_dict
    service_dict = UserService.from_dict(
        {
            "name": "dict_service",
            "key": 111,
            "supports_response": 2,  # ONLY
        }
    )
    assert service_dict.supports_response == SupportsResponseType.ONLY

    # Test to_dict
    service_to_dict = UserService(
        name="to_dict_service",
        key=222,
        supports_response=SupportsResponseType.OPTIONAL,
    )
    result = service_to_dict.to_dict()
    assert result["supports_response"] == 1


def test_execute_service_response():
    """Test ExecuteServiceResponse model."""
    # Test from protobuf with all fields
    pb = ExecuteServiceResponsePb(
        call_id=12345,
        success=True,
        error_message="",
        response_data=b'{"result": "ok"}',
    )
    response = ExecuteServiceResponse.from_pb(pb)
    assert response.call_id == 12345
    assert response.success is True
    assert response.error_message == ""
    assert response.response_data == b'{"result": "ok"}'

    # Test error response
    pb_error = ExecuteServiceResponsePb(
        call_id=67890,
        success=False,
        error_message="Service execution failed",
        response_data=b"",
    )
    response_error = ExecuteServiceResponse.from_pb(pb_error)
    assert response_error.call_id == 67890
    assert response_error.success is False
    assert response_error.error_message == "Service execution failed"
    assert response_error.response_data == b""

    # Test default values
    pb_default = ExecuteServiceResponsePb()
    response_default = ExecuteServiceResponse.from_pb(pb_default)
    assert response_default.call_id == 0
    assert response_default.success is False
    assert response_default.error_message == ""
    assert response_default.response_data == b""

    # Test from_dict
    response_dict = ExecuteServiceResponse.from_dict(
        {
            "call_id": 99999,
            "success": True,
            "error_message": "test",
            "response_data": b"data",
        }
    )
    assert response_dict.call_id == 99999
    assert response_dict.success is True
    assert response_dict.error_message == "test"
    assert response_dict.response_data == b"data"

    # Test to_dict
    response_to_dict = ExecuteServiceResponse(
        call_id=11111,
        success=True,
        error_message="",
        response_data=b"test_data",
    )
    result = response_to_dict.to_dict()
    assert result["call_id"] == 11111
    assert result["success"] is True
    assert result["error_message"] == ""
    assert result["response_data"] == b"test_data"
