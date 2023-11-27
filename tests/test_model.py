from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from google.protobuf import message

from aioesphomeapi.api_pb2 import (
    AlarmControlPanelStateResponse,
    BinarySensorStateResponse,
    BluetoothGATTCharacteristic,
    BluetoothGATTDescriptor,
    BluetoothGATTGetServicesResponse,
    ClimateStateResponse,
    CoverStateResponse,
    DeviceInfoResponse,
    FanStateResponse,
    HomeassistantServiceMap,
    HomeassistantServiceResponse,
    LightStateResponse,
    ListEntitiesAlarmControlPanelResponse,
    ListEntitiesBinarySensorResponse,
    ListEntitiesButtonResponse,
    ListEntitiesClimateResponse,
    ListEntitiesCoverResponse,
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
    LockStateResponse,
    MediaPlayerStateResponse,
    NumberStateResponse,
    SelectStateResponse,
    SensorStateResponse,
    ServiceArgType,
    SwitchStateResponse,
    TextSensorStateResponse,
    TextStateResponse,
)
from aioesphomeapi.model import (
    _TYPE_TO_NAME,
    AlarmControlPanelEntityState,
    AlarmControlPanelInfo,
    APIIntEnum,
    APIModelBase,
    APIVersion,
    BinarySensorInfo,
    BinarySensorState,
)
from aioesphomeapi.model import (
    BluetoothGATTCharacteristic as BluetoothGATTCharacteristicModel,
)
from aioesphomeapi.model import BluetoothGATTDescriptor as BluetoothGATTDescriptorModel
from aioesphomeapi.model import BluetoothGATTService as BluetoothGATTServiceModel
from aioesphomeapi.model import BluetoothGATTServices as BluetoothGATTServicesModel
from aioesphomeapi.model import (
    BluetoothProxyFeature,
    ButtonInfo,
    CameraInfo,
    ClimateInfo,
    ClimatePreset,
    ClimateState,
    CoverInfo,
    CoverState,
    DeviceInfo,
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
    NumberInfo,
    NumberState,
    SelectInfo,
    SelectState,
    SensorInfo,
    SensorState,
    SirenInfo,
    SwitchInfo,
    SwitchState,
    TextInfo,
    TextSensorInfo,
    TextSensorState,
    TextState,
    UserService,
    UserServiceArg,
    UserServiceArgType,
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
    val2: DummyIntEnum | None = converter_field(
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
        (SelectInfo, ListEntitiesSelectResponse),
        (SelectState, SelectStateResponse),
        (HomeassistantServiceCall, HomeassistantServiceResponse),
        (UserServiceArg, ListEntitiesServicesArgument),
        (UserService, ListEntitiesServicesResponse),
        (ButtonInfo, ListEntitiesButtonResponse),
        (LockInfo, ListEntitiesLockResponse),
        (LockEntityState, LockStateResponse),
        (MediaPlayerInfo, ListEntitiesMediaPlayerResponse),
        (MediaPlayerEntityState, MediaPlayerStateResponse),
        (AlarmControlPanelInfo, ListEntitiesAlarmControlPanelResponse),
        (AlarmControlPanelEntityState, AlarmControlPanelStateResponse),
        (TextState, TextStateResponse),
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
        (ClimateState(legacy_away=False), (1, 4), ClimatePreset.HOME),
        (ClimateState(legacy_away=True), (1, 4), ClimatePreset.AWAY),
        (
            ClimateState(legacy_away=True, preset=ClimatePreset.HOME),
            (1, 4),
            ClimatePreset.AWAY,
        ),
        (ClimateState(preset=ClimatePreset.HOME), (1, 5), ClimatePreset.HOME),
        (ClimateState(preset=ClimatePreset.BOOST), (1, 5), ClimatePreset.BOOST),
        (
            ClimateState(legacy_away=True, preset=ClimatePreset.BOOST),
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
        SelectInfo,
        SensorInfo,
        SirenInfo,
        SwitchInfo,
        TextSensorInfo,
        CameraInfo,
        ClimateInfo,
        LockInfo,
        MediaPlayerInfo,
        AlarmControlPanelInfo,
        TextInfo,
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
        supported_color_modes=[42],
    )
    assert info.supported_color_modes_compat(APIVersion(1, 5)) == capability
    assert info.supported_color_modes_compat(APIVersion(1, 9)) == [42]


@pytest.mark.asyncio
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
