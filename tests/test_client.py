from __future__ import annotations

import asyncio
import itertools
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from google.protobuf import message

from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.api_pb2 import (
    AlarmControlPanelCommandRequest,
    BinarySensorStateResponse,
    BluetoothConnectionsFreeResponse,
    BluetoothDeviceClearCacheResponse,
    BluetoothDeviceConnectionResponse,
    BluetoothDevicePairingResponse,
    BluetoothDeviceUnpairingResponse,
    BluetoothGATTErrorResponse,
    BluetoothGATTGetServicesDoneResponse,
    BluetoothGATTGetServicesResponse,
    BluetoothGATTNotifyDataResponse,
    BluetoothGATTNotifyResponse,
    BluetoothGATTReadResponse,
    BluetoothGATTService,
    BluetoothGATTWriteResponse,
    BluetoothLEAdvertisementResponse,
    BluetoothLERawAdvertisement,
    BluetoothLERawAdvertisementsResponse,
    ButtonCommandRequest,
    CameraImageRequest,
    CameraImageResponse,
    ClimateCommandRequest,
    CoverCommandRequest,
    DeviceInfoResponse,
    DisconnectResponse,
    ExecuteServiceArgument,
    ExecuteServiceRequest,
    FanCommandRequest,
    HomeassistantServiceResponse,
    LightCommandRequest,
    ListEntitiesBinarySensorResponse,
    ListEntitiesDoneResponse,
    ListEntitiesServicesResponse,
    LockCommandRequest,
    MediaPlayerCommandRequest,
    NumberCommandRequest,
    SelectCommandRequest,
    SirenCommandRequest,
    SubscribeHomeAssistantStateResponse,
    SubscribeLogsResponse,
    SwitchCommandRequest,
    TextCommandRequest,
)
from aioesphomeapi.client import APIClient
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.core import (
    APIConnectionError,
    BluetoothGATTAPIError,
    TimeoutAPIError,
    UnhandledAPIConnectionError,
)
from aioesphomeapi.model import (
    AlarmControlPanelCommand,
    APIVersion,
    BinarySensorInfo,
    BinarySensorState,
)
from aioesphomeapi.model import BluetoothGATTService as BluetoothGATTServiceModel
from aioesphomeapi.model import (
    BluetoothLEAdvertisement,
    CameraState,
    ClimateFanMode,
    ClimateMode,
    ClimatePreset,
    ClimateSwingMode,
    ESPHomeBluetoothGATTServices,
    FanDirection,
    FanSpeed,
    HomeassistantServiceCall,
    LegacyCoverCommand,
    LightColorCapability,
    LockCommand,
    MediaPlayerCommand,
    UserService,
    UserServiceArg,
    UserServiceArgType,
)
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState

from .common import (
    Estr,
    generate_plaintext_packet,
    get_mock_zeroconf,
    mock_data_received,
)
from .conftest import PatchableAPIConnection


@pytest.fixture
def auth_client():
    client = APIClient(
        address="fake.address",
        port=6052,
        password=None,
    )
    with patch.object(client, "_connection") as conn:
        conn.is_connected = True
        yield client


def patch_response_complex(client: APIClient, messages):
    async def patched(req, app, stop, msg_types, timeout):
        resp = []
        for msg in messages:
            if app(msg):
                resp.append(msg)
            if stop(msg):
                break
        else:
            raise ValueError("Response never stopped")
        return resp

    client._connection.send_messages_await_response_complex = patched


def patch_response_callback(client: APIClient):
    on_message = None

    def patched(req, callback, msg_types):
        nonlocal on_message
        on_message = callback

    client._connection.send_message_callback_response = patched

    async def ret(send):
        on_message(send)

    return ret


def patch_send(client: APIClient):
    send = client._connection.send_message = MagicMock()
    return send


def patch_api_version(client: APIClient, version: APIVersion):
    client._connection.api_version = version


def test_expected_name(auth_client: APIClient) -> None:
    """Ensure expected name can be set externally."""
    assert auth_client.expected_name is None
    auth_client.expected_name = "awesome"
    assert auth_client.expected_name == "awesome"


@pytest.mark.asyncio
async def test_connect_backwards_compat() -> None:
    """Verify connect is a thin wrapper around start_connection and finish_connection."""

    class PatchableApiClient(APIClient):
        pass

    cli = PatchableApiClient("host", 1234, None)
    with patch.object(cli, "start_connection") as mock_start_connection, patch.object(
        cli, "finish_connection"
    ) as mock_finish_connection:
        await cli.connect()

    assert mock_start_connection.mock_calls == [call(None)]
    assert mock_finish_connection.mock_calls == [call(False)]


@pytest.mark.asyncio
async def test_finish_connection_wraps_exceptions_as_unhandled_api_error() -> None:
    """Verify finish_connect re-wraps exceptions as UnhandledAPIError."""

    cli = APIClient("1.2.3.4", 1234, None)
    loop = asyncio.get_event_loop()
    with patch(
        "aioesphomeapi.client.APIConnection", PatchableAPIConnection
    ), patch.object(loop, "sock_connect"):
        await cli.start_connection()

    with patch.object(
        cli._connection,
        "send_messages_await_response_complex",
        side_effect=Exception("foo"),
    ):
        with pytest.raises(UnhandledAPIConnectionError, match="foo"):
            await cli.finish_connection(False)


@pytest.mark.asyncio
async def test_connect_while_already_connected(auth_client: APIClient) -> None:
    """Test connecting while already connected raises."""
    with pytest.raises(APIConnectionError):
        await auth_client.start_connection()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "input, output",
    [
        (
            [ListEntitiesBinarySensorResponse(), ListEntitiesDoneResponse()],
            ([BinarySensorInfo()], []),
        ),
        (
            [ListEntitiesServicesResponse(), ListEntitiesDoneResponse()],
            ([], [UserService()]),
        ),
    ],
)
async def test_list_entities(
    auth_client: APIClient, input: dict[str, Any], output: dict[str, Any]
) -> None:
    patch_response_complex(auth_client, input)
    resp = await auth_client.list_entities_services()
    assert resp == output


@pytest.mark.asyncio
async def test_subscribe_states(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_state = MagicMock()
    await auth_client.subscribe_states(on_state)
    on_state.assert_not_called()

    await send(BinarySensorStateResponse())
    on_state.assert_called_once_with(BinarySensorState())


@pytest.mark.asyncio
async def test_subscribe_states_camera(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_state = MagicMock()
    await auth_client.subscribe_states(on_state)
    await send(CameraImageResponse(key=1, data=b"asdf"))
    on_state.assert_not_called()

    await send(CameraImageResponse(key=1, data=b"qwer", done=True))
    on_state.assert_called_once_with(CameraState(key=1, data=b"asdfqwer"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1), dict(key=1)),
        (
            dict(key=1, position=1.0),
            dict(
                key=1, has_legacy_command=True, legacy_command=LegacyCoverCommand.OPEN
            ),
        ),
        (
            dict(key=1, position=0.0),
            dict(
                key=1, has_legacy_command=True, legacy_command=LegacyCoverCommand.CLOSE
            ),
        ),
        (
            dict(key=1, stop=True),
            dict(
                key=1, has_legacy_command=True, legacy_command=LegacyCoverCommand.STOP
            ),
        ),
    ],
)
async def test_cover_command_legacy(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)
    patch_api_version(auth_client, APIVersion(1, 0))

    await auth_client.cover_command(**cmd)
    send.assert_called_once_with(CoverCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1), dict(key=1)),
        (dict(key=1, position=0.5), dict(key=1, has_position=True, position=0.5)),
        (dict(key=1, position=0.0), dict(key=1, has_position=True, position=0.0)),
        (dict(key=1, stop=True), dict(key=1, stop=True)),
        (
            dict(key=1, position=1.0, tilt=0.8),
            dict(key=1, has_position=True, position=1.0, has_tilt=True, tilt=0.8),
        ),
    ],
)
async def test_cover_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)
    patch_api_version(auth_client, APIVersion(1, 1))

    await auth_client.cover_command(**cmd)
    send.assert_called_once_with(CoverCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1), dict(key=1)),
        (dict(key=1, state=True), dict(key=1, has_state=True, state=True)),
        (
            dict(key=1, speed=FanSpeed.LOW),
            dict(key=1, has_speed=True, speed=FanSpeed.LOW),
        ),
        (
            dict(key=1, speed_level=10),
            dict(key=1, has_speed_level=True, speed_level=10),
        ),
        (
            dict(key=1, oscillating=False),
            dict(key=1, has_oscillating=True, oscillating=False),
        ),
        (
            dict(key=1, direction=FanDirection.REVERSE),
            dict(key=1, has_direction=True, direction=FanDirection.REVERSE),
        ),
    ],
)
async def test_fan_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.fan_command(**cmd)
    send.assert_called_once_with(FanCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1), dict(key=1)),
        (dict(key=1, state=True), dict(key=1, has_state=True, state=True)),
        (dict(key=1, brightness=0.8), dict(key=1, has_brightness=True, brightness=0.8)),
        (
            dict(key=1, rgb=(0.1, 0.5, 1.0)),
            dict(key=1, has_rgb=True, red=0.1, green=0.5, blue=1.0),
        ),
        (dict(key=1, white=0.0), dict(key=1, has_white=True, white=0.0)),
        (
            dict(key=1, color_temperature=0.0),
            dict(key=1, has_color_temperature=True, color_temperature=0.0),
        ),
        (
            dict(key=1, color_brightness=0.0),
            dict(key=1, has_color_brightness=True, color_brightness=0.0),
        ),
        (
            dict(key=1, cold_white=1.0, warm_white=2.0),
            dict(
                key=1,
                has_cold_white=True,
                cold_white=1.0,
                has_warm_white=True,
                warm_white=2.0,
            ),
        ),
        (
            dict(key=1, transition_length=0.1),
            dict(key=1, has_transition_length=True, transition_length=100),
        ),
        (
            dict(key=1, flash_length=0.1),
            dict(key=1, has_flash_length=True, flash_length=100),
        ),
        (dict(key=1, effect="special"), dict(key=1, has_effect=True, effect="special")),
        (
            dict(
                key=1,
                color_mode=LightColorCapability.COLOR_TEMPERATURE,
                color_temperature=153.0,
            ),
            dict(
                key=1,
                has_color_mode=True,
                color_mode=LightColorCapability.COLOR_TEMPERATURE,
                has_color_temperature=True,
                color_temperature=153.0,
            ),
        ),
    ],
)
async def test_light_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.light_command(**cmd)
    send.assert_called_once_with(LightCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1, state=False), dict(key=1, state=False)),
        (dict(key=1, state=True), dict(key=1, state=True)),
    ],
)
async def test_switch_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.switch_command(**cmd)
    send.assert_called_once_with(SwitchCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, preset=ClimatePreset.HOME),
            dict(key=1, has_legacy_away=True, legacy_away=False),
        ),
        (
            dict(key=1, preset=ClimatePreset.AWAY),
            dict(key=1, has_legacy_away=True, legacy_away=True),
        ),
    ],
)
async def test_climate_command_legacy(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)
    patch_api_version(auth_client, APIVersion(1, 4))

    await auth_client.climate_command(**cmd)
    send.assert_called_once_with(ClimateCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, mode=ClimateMode.HEAT),
            dict(key=1, has_mode=True, mode=ClimateMode.HEAT),
        ),
        (
            dict(key=1, target_temperature=21.0),
            dict(key=1, has_target_temperature=True, target_temperature=21.0),
        ),
        (
            dict(key=1, target_temperature_low=21.0),
            dict(key=1, has_target_temperature_low=True, target_temperature_low=21.0),
        ),
        (
            dict(key=1, target_temperature_high=21.0),
            dict(key=1, has_target_temperature_high=True, target_temperature_high=21.0),
        ),
        (
            dict(key=1, fan_mode=ClimateFanMode.LOW),
            dict(key=1, has_fan_mode=True, fan_mode=ClimateFanMode.LOW),
        ),
        (
            dict(key=1, swing_mode=ClimateSwingMode.OFF),
            dict(key=1, has_swing_mode=True, swing_mode=ClimateSwingMode.OFF),
        ),
        (
            dict(key=1, custom_fan_mode="asdf"),
            dict(key=1, has_custom_fan_mode=True, custom_fan_mode="asdf"),
        ),
        (
            dict(key=1, preset=ClimatePreset.AWAY),
            dict(key=1, has_preset=True, preset=ClimatePreset.AWAY),
        ),
        (
            dict(key=1, custom_preset="asdf"),
            dict(key=1, has_custom_preset=True, custom_preset="asdf"),
        ),
    ],
)
async def test_climate_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)
    patch_api_version(auth_client, APIVersion(1, 5))

    await auth_client.climate_command(**cmd)
    send.assert_called_once_with(ClimateCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1, state=0.0), dict(key=1, state=0.0)),
        (dict(key=1, state=100.0), dict(key=1, state=100.0)),
    ],
)
async def test_number_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.number_command(**cmd)
    send.assert_called_once_with(NumberCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1, command=LockCommand.LOCK), dict(key=1, command=LockCommand.LOCK)),
        (
            dict(key=1, command=LockCommand.UNLOCK),
            dict(key=1, command=LockCommand.UNLOCK),
        ),
        (dict(key=1, command=LockCommand.OPEN), dict(key=1, command=LockCommand.OPEN)),
        (
            dict(key=1, command=LockCommand.OPEN, code="1234"),
            dict(key=1, command=LockCommand.OPEN, code="1234"),
        ),
    ],
)
async def test_lock_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.lock_command(**cmd)
    send.assert_called_once_with(LockCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1, state="One"), dict(key=1, state="One")),
        (dict(key=1, state="Two"), dict(key=1, state="Two")),
    ],
)
async def test_select_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.select_command(**cmd)
    send.assert_called_once_with(SelectCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, command=MediaPlayerCommand.MUTE),
            dict(key=1, has_command=True, command=MediaPlayerCommand.MUTE),
        ),
        (
            dict(key=1, volume=1.0),
            dict(key=1, has_volume=True, volume=1.0),
        ),
        (
            dict(key=1, media_url="http://example.com"),
            dict(key=1, has_media_url=True, media_url="http://example.com"),
        ),
    ],
)
async def test_media_player_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.media_player_command(**cmd)
    send.assert_called_once_with(MediaPlayerCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1), dict(key=1)),
    ],
)
async def test_button_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.button_command(**cmd)
    send.assert_called_once_with(ButtonCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1, state=True), dict(key=1, state=True, has_state=True)),
        (dict(key=1, state=False), dict(key=1, state=False, has_state=True)),
        (dict(key=1, state=None), dict(key=1, state=None, has_state=False)),
        (
            dict(key=1, state=True, tone="any"),
            dict(key=1, state=True, has_state=True, has_tone=True, tone="any"),
        ),
        (
            dict(key=1, state=True, tone=None),
            dict(key=1, state=True, has_state=True, has_tone=False, tone=None),
        ),
        (
            dict(key=1, state=True, volume=5),
            dict(key=1, state=True, has_volume=True, volume=5, has_state=True),
        ),
        (
            dict(key=1, state=True, duration=5),
            dict(key=1, state=True, has_duration=True, duration=5, has_state=True),
        ),
    ],
)
async def test_siren_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.siren_command(**cmd)
    send.assert_called_once_with(SirenCommandRequest(**req))


@pytest.mark.asyncio
async def test_execute_service(auth_client: APIClient) -> None:
    send = patch_send(auth_client)
    patch_api_version(auth_client, APIVersion(1, 3))

    service = UserService(
        name="my_service",
        key=1,
        args=[
            UserServiceArg(name="arg1", type=UserServiceArgType.BOOL),
            UserServiceArg(name="arg2", type=UserServiceArgType.INT),
            UserServiceArg(name="arg3", type=UserServiceArgType.FLOAT),
            UserServiceArg(name="arg4", type=UserServiceArgType.STRING),
            UserServiceArg(name="arg5", type=UserServiceArgType.BOOL_ARRAY),
            UserServiceArg(name="arg6", type=UserServiceArgType.INT_ARRAY),
            UserServiceArg(name="arg7", type=UserServiceArgType.FLOAT_ARRAY),
            UserServiceArg(name="arg8", type=UserServiceArgType.STRING_ARRAY),
        ],
    )

    with pytest.raises(KeyError):
        await auth_client.execute_service(service, data={})

    await auth_client.execute_service(
        service,
        data={
            "arg1": False,
            "arg2": 42,
            "arg3": 99.0,
            "arg4": "asdf",
            "arg5": [False, True, False],
            "arg6": [42, 10, 9],
            "arg7": [0.0, -100.0],
            "arg8": [],
        },
    )
    send.assert_called_once_with(
        ExecuteServiceRequest(
            key=1,
            args=[
                ExecuteServiceArgument(bool_=False),
                ExecuteServiceArgument(int_=42),
                ExecuteServiceArgument(float_=99.0),
                ExecuteServiceArgument(string_="asdf"),
                ExecuteServiceArgument(bool_array=[False, True, False]),
                ExecuteServiceArgument(int_array=[42, 10, 9]),
                ExecuteServiceArgument(float_array=[0.0, -100.0]),
                ExecuteServiceArgument(string_array=[]),
            ],
        )
    )
    send.reset_mock()

    patch_api_version(auth_client, APIVersion(1, 2))
    service = UserService(
        name="my_service",
        key=2,
        args=[
            UserServiceArg(name="arg1", type=UserServiceArgType.BOOL),
            UserServiceArg(name="arg2", type=UserServiceArgType.INT),
        ],
    )

    # Test legacy_int
    await auth_client.execute_service(
        service,
        data={
            "arg1": False,
            "arg2": 42,
        },
    )
    send.assert_called_once_with(
        ExecuteServiceRequest(
            key=2,
            args=[
                ExecuteServiceArgument(bool_=False),
                ExecuteServiceArgument(legacy_int=42),
            ],
        )
    )
    send.reset_mock()

    # Test arg order
    await auth_client.execute_service(
        service,
        data={
            "arg2": 42,
            "arg1": False,
        },
    )
    send.assert_called_once_with(
        ExecuteServiceRequest(
            key=2,
            args=[
                ExecuteServiceArgument(bool_=False),
                ExecuteServiceArgument(legacy_int=42),
            ],
        )
    )
    send.reset_mock()


@pytest.mark.asyncio
async def test_request_single_image(auth_client: APIClient) -> None:
    send = patch_send(auth_client)

    await auth_client.request_single_image()
    send.assert_called_once_with(CameraImageRequest(single=True, stream=False))


@pytest.mark.asyncio
async def test_request_image_stream(auth_client: APIClient) -> None:
    send = patch_send(auth_client)

    await auth_client.request_image_stream()
    send.assert_called_once_with(CameraImageRequest(single=False, stream=True))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, command=AlarmControlPanelCommand.ARM_AWAY),
            dict(key=1, command=AlarmControlPanelCommand.ARM_AWAY, code=None),
        ),
        (
            dict(key=1, command=AlarmControlPanelCommand.ARM_HOME),
            dict(key=1, command=AlarmControlPanelCommand.ARM_HOME, code=None),
        ),
        (
            dict(key=1, command=AlarmControlPanelCommand.DISARM, code="1234"),
            dict(key=1, command=AlarmControlPanelCommand.DISARM, code="1234"),
        ),
    ],
)
async def test_alarm_panel_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.alarm_control_panel_command(**cmd)
    send.assert_called_once_with(AlarmControlPanelCommandRequest(**req))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1, state="hello world"), dict(key=1, state="hello world")),
        (dict(key=1, state="goodbye"), dict(key=1, state="goodbye")),
    ],
)
async def test_text_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    await auth_client.text_command(**cmd)
    send.assert_called_once_with(TextCommandRequest(**req))


@pytest.mark.asyncio
async def test_noise_psk_handles_subclassed_string():
    """Test that the noise_psk gets converted to a string."""

    class PatchableAPIClient(APIClient):
        pass

    cli = PatchableAPIClient(
        address=Estr("1.2.3.4"),
        port=6052,
        password=None,
        noise_psk=Estr("QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="),
        expected_name=Estr("mydevice"),
    )
    # Make sure its not a subclassed string
    assert type(cli._params.noise_psk) is str
    assert type(cli._params.address) is str
    assert type(cli._params.expected_name) is str

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    with patch.object(cli, "start_connection"), patch.object(cli, "finish_connection"):
        await rl.start()
        for _ in range(3):
            await asyncio.sleep(0)

    rl.stop_callback()
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_no_noise_psk():
    """Test not using a noise_psk."""
    cli = APIClient(
        address=Estr("1.2.3.4"),
        port=6052,
        password=None,
        noise_psk=None,
        expected_name=Estr("mydevice"),
    )
    # Make sure its not a subclassed string
    assert cli._params.noise_psk is None
    assert type(cli._params.address) is str
    assert type(cli._params.expected_name) is str


@pytest.mark.asyncio
async def test_empty_noise_psk_or_expected_name():
    """Test an empty noise_psk is treated as None."""
    cli = APIClient(
        address=Estr("1.2.3.4"),
        port=6052,
        password=None,
        noise_psk="",
        expected_name="",
    )
    assert cli._params.noise_psk is None
    assert type(cli._params.address) is str
    assert cli._params.expected_name is None


@pytest.mark.asyncio
async def test_bluetooth_disconnect(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_device_disconnect."""
    client, connection, transport, protocol = api_client
    disconnect_task = asyncio.create_task(client.bluetooth_device_disconnect(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await disconnect_task


@pytest.mark.asyncio
async def test_bluetooth_pair(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_device_pair."""
    client, connection, transport, protocol = api_client
    pair_task = asyncio.create_task(client.bluetooth_device_pair(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDevicePairingResponse(address=1234)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await pair_task


@pytest.mark.asyncio
async def test_bluetooth_unpair(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_device_unpair."""
    client, connection, transport, protocol = api_client
    unpair_task = asyncio.create_task(client.bluetooth_device_unpair(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceUnpairingResponse(address=1234)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await unpair_task


@pytest.mark.asyncio
async def test_bluetooth_clear_cache(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_device_clear_cache."""
    client, connection, transport, protocol = api_client
    clear_task = asyncio.create_task(client.bluetooth_device_clear_cache(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceClearCacheResponse(address=1234)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await clear_task


@pytest.mark.asyncio
async def test_device_info(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test fetching device info."""
    client, connection, transport, protocol = api_client
    assert client.log_name == "mydevice.local"
    device_info_task = asyncio.create_task(client.device_info())
    await asyncio.sleep(0)
    response: message.Message = DeviceInfoResponse(
        name="realname",
        friendly_name="My Device",
        has_deep_sleep=True,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    device_info = await device_info_task
    assert device_info.name == "realname"
    assert device_info.friendly_name == "My Device"
    assert device_info.has_deep_sleep
    assert client.log_name == "realname @ 10.0.0.512"
    disconnect_task = asyncio.create_task(client.disconnect())
    await asyncio.sleep(0)
    response: message.Message = DisconnectResponse()
    mock_data_received(protocol, generate_plaintext_packet(response))
    await disconnect_task
    with pytest.raises(APIConnectionError, match="CLOSED"):
        await client.device_info()


@pytest.mark.asyncio
async def test_bluetooth_gatt_read(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_read."""
    client, connection, transport, protocol = api_client
    read_task = asyncio.create_task(client.bluetooth_gatt_read(1234, 1234))
    await asyncio.sleep(0)

    other_response: message.Message = BluetoothGATTReadResponse(
        address=1234, handle=4567, data=b"4567"
    )
    mock_data_received(protocol, generate_plaintext_packet(other_response))

    response: message.Message = BluetoothGATTReadResponse(
        address=1234, handle=1234, data=b"1234"
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    assert await read_task == b"1234"


@pytest.mark.asyncio
async def test_bluetooth_gatt_read_descriptor(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_read_descriptor."""
    client, connection, transport, protocol = api_client
    read_task = asyncio.create_task(client.bluetooth_gatt_read_descriptor(1234, 1234))
    await asyncio.sleep(0)

    other_response: message.Message = BluetoothGATTReadResponse(
        address=1234, handle=4567, data=b"4567"
    )
    mock_data_received(protocol, generate_plaintext_packet(other_response))

    response: message.Message = BluetoothGATTReadResponse(
        address=1234, handle=1234, data=b"1234"
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    assert await read_task == b"1234"


@pytest.mark.asyncio
async def test_bluetooth_gatt_write(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_write."""
    client, connection, transport, protocol = api_client
    write_task = asyncio.create_task(
        client.bluetooth_gatt_write(1234, 1234, b"1234", True)
    )
    await asyncio.sleep(0)

    other_response: message.Message = BluetoothGATTWriteResponse(
        address=1234, handle=4567
    )
    mock_data_received(protocol, generate_plaintext_packet(other_response))

    response: message.Message = BluetoothGATTWriteResponse(address=1234, handle=1234)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await write_task


@pytest.mark.asyncio
async def test_bluetooth_gatt_write_without_response(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_write without response."""
    client, connection, transport, protocol = api_client
    transport.reset_mock()
    write_task = asyncio.create_task(
        client.bluetooth_gatt_write(1234, 1234, b"1234", False)
    )
    await asyncio.sleep(0)
    await write_task
    assert transport.mock_calls[0][1][0] == b'\x00\x0cK\x08\xd2\t\x10\xd2\t"\x041234'

    with pytest.raises(TimeoutAPIError, match="BluetoothGATTWriteResponse"):
        await client.bluetooth_gatt_write(1234, 1234, b"1234", True, timeout=0)


@pytest.mark.asyncio
async def test_bluetooth_gatt_write_descriptor(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_write_descriptor."""
    client, connection, transport, protocol = api_client
    write_task = asyncio.create_task(
        client.bluetooth_gatt_write_descriptor(1234, 1234, b"1234", True)
    )
    await asyncio.sleep(0)

    other_response: message.Message = BluetoothGATTWriteResponse(
        address=1234, handle=4567
    )
    mock_data_received(protocol, generate_plaintext_packet(other_response))

    response: message.Message = BluetoothGATTWriteResponse(address=1234, handle=1234)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await write_task


@pytest.mark.asyncio
async def test_bluetooth_gatt_write_descriptor_without_response(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_write_descriptor without response."""
    client, connection, transport, protocol = api_client
    transport.reset_mock()
    write_task = asyncio.create_task(
        client.bluetooth_gatt_write_descriptor(
            1234, 1234, b"1234", wait_for_response=False
        )
    )
    await asyncio.sleep(0)
    await write_task
    assert transport.mock_calls[0][1][0] == b"\x00\x0cM\x08\xd2\t\x10\xd2\t\x1a\x041234"

    with pytest.raises(TimeoutAPIError, match="BluetoothGATTWriteResponse"):
        await client.bluetooth_gatt_write_descriptor(1234, 1234, b"1234", timeout=0)


@pytest.mark.asyncio
async def test_bluetooth_gatt_get_services(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_get_services success case."""
    client, connection, transport, protocol = api_client
    services_task = asyncio.create_task(client.bluetooth_gatt_get_services(1234))
    await asyncio.sleep(0)
    service1: message.Message = BluetoothGATTService(
        uuid=[1, 1], handle=1, characteristics=[]
    )
    response: message.Message = BluetoothGATTGetServicesResponse(
        address=1234, services=[service1]
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    done_response: message.Message = BluetoothGATTGetServicesDoneResponse(address=1234)
    mock_data_received(protocol, generate_plaintext_packet(done_response))

    services = await services_task
    assert services == ESPHomeBluetoothGATTServices(
        address=1234,
        services=[BluetoothGATTServiceModel(uuid=[1, 1], handle=1, characteristics=[])],
    )


@pytest.mark.asyncio
async def test_bluetooth_gatt_get_services_errors(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_get_services with a failure."""
    client, connection, transport, protocol = api_client
    services_task = asyncio.create_task(client.bluetooth_gatt_get_services(1234))
    await asyncio.sleep(0)
    service1: message.Message = BluetoothGATTService(
        uuid=[1, 1], handle=1, characteristics=[]
    )
    response: message.Message = BluetoothGATTGetServicesResponse(
        address=1234, services=[service1]
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    done_response: message.Message = BluetoothGATTErrorResponse(address=1234)
    mock_data_received(protocol, generate_plaintext_packet(done_response))

    with pytest.raises(BluetoothGATTAPIError):
        await services_task


@pytest.mark.asyncio
async def test_bluetooth_gatt_start_notify(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_start_notify."""
    client, connection, transport, protocol = api_client
    notifies = []

    handlers_before = len(
        list(itertools.chain(*connection._get_message_handlers().values()))
    )

    def on_bluetooth_gatt_notify(handle: int, data: bytearray) -> None:
        notifies.append((handle, data))

    notify_task = asyncio.create_task(
        client.bluetooth_gatt_start_notify(1234, 1, on_bluetooth_gatt_notify)
    )
    await asyncio.sleep(0)
    notify_response: message.Message = BluetoothGATTNotifyResponse(
        address=1234, handle=1
    )
    data_response: message.Message = BluetoothGATTNotifyDataResponse(
        address=1234, handle=1, data=b"gotit"
    )
    mock_data_received(
        protocol,
        generate_plaintext_packet(notify_response)
        + generate_plaintext_packet(data_response),
    )

    cancel_cb, abort_cb = await notify_task
    assert notifies == [(1, b"gotit")]

    second_data_response: message.Message = BluetoothGATTNotifyDataResponse(
        address=1234, handle=1, data=b"after finished"
    )
    mock_data_received(protocol, generate_plaintext_packet(second_data_response))
    assert notifies == [(1, b"gotit"), (1, b"after finished")]
    await cancel_cb()

    assert (
        len(list(itertools.chain(*connection._get_message_handlers().values())))
        == handlers_before
    )
    # Ensure abort callback is a no-op after cancel
    # and doesn't raise
    abort_cb()


@pytest.mark.asyncio
async def test_bluetooth_gatt_start_notify_fails(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_start_notify failure does not leak."""
    client, connection, transport, protocol = api_client
    notifies = []

    def on_bluetooth_gatt_notify(handle: int, data: bytearray) -> None:
        notifies.append((handle, data))

    handlers_before = len(
        list(itertools.chain(*connection._get_message_handlers().values()))
    )

    with patch.object(
        connection,
        "send_messages_await_response_complex",
        side_effect=APIConnectionError,
    ), pytest.raises(APIConnectionError):
        await client.bluetooth_gatt_start_notify(1234, 1, on_bluetooth_gatt_notify)

    assert (
        len(list(itertools.chain(*connection._get_message_handlers().values())))
        == handlers_before
    )


@pytest.mark.asyncio
async def test_subscribe_bluetooth_le_advertisements(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_bluetooth_le_advertisements."""
    client, connection, transport, protocol = api_client
    advs = []

    def on_bluetooth_le_advertisements(adv: BluetoothLEAdvertisement) -> None:
        advs.append(adv)

    unsub = await client.subscribe_bluetooth_le_advertisements(
        on_bluetooth_le_advertisements
    )
    await asyncio.sleep(0)
    response: message.Message = BluetoothLEAdvertisementResponse(
        address=1234,
        name=b"mydevice",
        rssi=-50,
        service_uuids=["1234"],
        service_data={},
        manufacturer_data={},
        address_type=1,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    assert advs == [
        BluetoothLEAdvertisement(
            address=1234,
            name="mydevice",
            rssi=-50,
            service_uuids=["000034-0000-1000-8000-00805f9b34fb"],
            manufacturer_data={},
            service_data={},
            address_type=1,
        )
    ]
    unsub()


@pytest.mark.asyncio
async def test_subscribe_bluetooth_le_raw_advertisements(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_bluetooth_le_raw_advertisements."""
    client, connection, transport, protocol = api_client
    adv_groups = []

    def on_raw_bluetooth_le_advertisements(
        advs: list[BluetoothLERawAdvertisementsResponse],
    ) -> None:
        adv_groups.append(advs)

    unsub = await client.subscribe_bluetooth_le_raw_advertisements(
        on_raw_bluetooth_le_advertisements
    )
    await asyncio.sleep(0)

    response: message.Message = BluetoothLERawAdvertisementsResponse(
        advertisements=[
            BluetoothLERawAdvertisement(
                address=1234,
                rssi=-50,
                address_type=1,
                data=b"1234",
            )
        ]
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    assert len(adv_groups) == 1
    first_adv = adv_groups[0][0]
    assert first_adv.address == 1234
    assert first_adv.rssi == -50
    assert first_adv.address_type == 1
    assert first_adv.data == b"1234"
    unsub()


@pytest.mark.asyncio
async def test_subscribe_bluetooth_connections_free(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_bluetooth_connections_free."""
    client, connection, transport, protocol = api_client
    connections = []

    def on_bluetooth_connections_free(free: int, limit: int) -> None:
        connections.append((free, limit))

    unsub = await client.subscribe_bluetooth_connections_free(
        on_bluetooth_connections_free
    )
    await asyncio.sleep(0)
    response: message.Message = BluetoothConnectionsFreeResponse(free=2, limit=3)
    mock_data_received(protocol, generate_plaintext_packet(response))

    assert connections == [(2, 3)]
    unsub()


@pytest.mark.asyncio
async def test_subscribe_home_assistant_states(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_home_assistant_states."""
    client, connection, transport, protocol = api_client
    states = []

    def on_subscribe_home_assistant_states(
        entity_id: str, attribute: str | None
    ) -> None:
        states.append((entity_id, attribute))

    await client.subscribe_home_assistant_states(on_subscribe_home_assistant_states)
    await asyncio.sleep(0)

    response: message.Message = SubscribeHomeAssistantStateResponse(
        entity_id="sensor.red", attribute="any"
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    assert states == [("sensor.red", "any")]


@pytest.mark.asyncio
async def test_subscribe_logs(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_logs = MagicMock()
    await auth_client.subscribe_logs(on_logs)
    log_msg = SubscribeLogsResponse(level=1, message=b"asdf")
    await send(log_msg)
    on_logs.assert_called_with(log_msg)


@pytest.mark.asyncio
async def test_subscribe_service_calls(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_service_call = MagicMock()
    await auth_client.subscribe_service_calls(on_service_call)
    service_msg = HomeassistantServiceResponse(service="bob")
    await send(service_msg)
    on_service_call.assert_called_with(HomeassistantServiceCall.from_pb(service_msg))


@pytest.mark.asyncio
async def test_set_debug(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test set_debug."""
    client, connection, transport, protocol = api_client
    response: message.Message = DeviceInfoResponse(
        name="realname",
        friendly_name="My Device",
        has_deep_sleep=True,
    )

    caplog.set_level(logging.DEBUG)

    client.set_debug(True)
    assert client.log_name == "mydevice.local"
    device_info_task = asyncio.create_task(client.device_info())
    await asyncio.sleep(0)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await device_info_task

    assert "My Device" in caplog.text
    caplog.clear()
    client.set_debug(False)
    device_info_task = asyncio.create_task(client.device_info())
    await asyncio.sleep(0)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await device_info_task
    assert "My Device" not in caplog.text


@pytest.mark.asyncio
async def test_force_disconnect(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test force disconnect can be called multiple times."""
    client, connection, transport, protocol = api_client
    await client.disconnect(force=True)
    assert connection.is_connected is False
    await client.disconnect(force=False)
    assert connection.is_connected is False
