from __future__ import annotations

import asyncio
import contextlib
from functools import partial
import itertools
import logging
import socket
from typing import Any
from unittest.mock import AsyncMock, MagicMock, call, create_autospec, patch

from google.protobuf import message
import pytest

from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.api_pb2 import (
    AlarmControlPanelCommandRequest,
    BinarySensorStateResponse,
    BluetoothConnectionsFreeResponse,
    BluetoothDeviceClearCacheResponse,
    BluetoothDeviceConnectionResponse,
    BluetoothDevicePairingResponse,
    BluetoothDeviceRequest,
    BluetoothDeviceUnpairingResponse,
    BluetoothGATTCharacteristic,
    BluetoothGATTDescriptor,
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
    BluetoothScannerMode,
    BluetoothScannerSetModeRequest,
    BluetoothScannerState,
    BluetoothScannerStateResponse,
    BluetoothServiceData,
    ButtonCommandRequest,
    CameraImageRequest,
    CameraImageResponse,
    ClimateCommandRequest,
    CoverCommandRequest,
    DateCommandRequest,
    DateTimeCommandRequest,
    DeviceInfoResponse,
    DisconnectResponse,
    ExecuteServiceArgument,
    ExecuteServiceRequest,
    FanCommandRequest,
    HomeassistantServiceResponse,
    HomeAssistantStateResponse,
    LightCommandRequest,
    ListEntitiesBinarySensorResponse,
    ListEntitiesDoneResponse,
    ListEntitiesServicesResponse,
    LockCommandRequest,
    MediaPlayerCommandRequest,
    NoiseEncryptionSetKeyRequest,
    NoiseEncryptionSetKeyResponse,
    NumberCommandRequest,
    SelectCommandRequest,
    SirenCommandRequest,
    SubscribeHomeAssistantStateResponse,
    SubscribeLogsResponse,
    SubscribeVoiceAssistantRequest,
    SwitchCommandRequest,
    TextCommandRequest,
    TimeCommandRequest,
    UpdateCommandRequest,
    ValveCommandRequest,
    VoiceAssistantAnnounceFinished,
    VoiceAssistantAnnounceRequest,
    VoiceAssistantAudio,
    VoiceAssistantAudioSettings,
    VoiceAssistantConfigurationRequest,
    VoiceAssistantConfigurationResponse,
    VoiceAssistantEventData,
    VoiceAssistantEventResponse,
    VoiceAssistantRequest,
    VoiceAssistantResponse,
    VoiceAssistantSetConfiguration,
    VoiceAssistantTimerEventResponse,
    VoiceAssistantWakeWord,
)
from aioesphomeapi.client import APIClient, BluetoothConnectionDroppedError
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
    BluetoothDeviceRequestType,
    BluetoothGATTService as BluetoothGATTServiceModel,
    BluetoothLEAdvertisement,
    BluetoothProxyFeature,
    BluetoothScannerMode as BluetoothScannerModeModel,
    BluetoothScannerStateResponse as BluetoothScannerStateResponseModel,
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
    UpdateCommand,
    UserService,
    UserServiceArg,
    UserServiceArgType,
    VoiceAssistantAnnounceFinished as VoiceAssistantAnnounceFinishedModel,
    VoiceAssistantAudioSettings as VoiceAssistantAudioSettingsModel,
    VoiceAssistantConfigurationResponse as VoiceAssistantConfigurationResponseModel,
    VoiceAssistantEventType as VoiceAssistantEventModelType,
    VoiceAssistantTimerEventType as VoiceAssistantTimerEventModelType,
)
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState

from .common import (
    Estr,
    generate_plaintext_packet,
    generate_split_plaintext_packet,
    get_mock_zeroconf,
    mock_data_received,
)
from .conftest import PatchableAPIClient, PatchableAPIConnection


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

    def cancelled_on_message(_):
        """A callback that does nothing."""

    def cancel_callable():
        nonlocal on_message
        on_message = cancelled_on_message

    def patched(req, callback, msg_types):
        nonlocal on_message
        on_message = callback
        return cancel_callable

    client._connection.send_message_callback_response = patched

    async def ret(send):
        on_message(send)

    return ret


def patch_send(client: APIClient):
    send = client._connection.send_message = MagicMock()
    return send


def patch_api_version(client: APIClient, version: APIVersion):
    client._connection.api_version = version


async def test_expected_name(auth_client: APIClient) -> None:
    """Ensure expected name can be set externally."""
    assert auth_client.expected_name is None
    auth_client.expected_name = "awesome"
    assert auth_client.expected_name == "awesome"


async def test_connect_backwards_compat() -> None:
    """Verify connect is a thin wrapper around start_resolve_host, start_connection and finish_connection."""

    cli = PatchableAPIClient("host", 1234, None)
    with (
        patch.object(cli, "start_resolve_host") as mock_start_resolve_host,
        patch.object(cli, "start_connection") as mock_start_connection,
        patch.object(cli, "finish_connection") as mock_finish_connection,
    ):
        await cli.connect()

    assert mock_start_resolve_host.mock_calls == [call(None)]
    assert mock_start_connection.mock_calls == [call()]
    assert mock_finish_connection.mock_calls == [call(False)]


async def test_finish_connection_wraps_exceptions_as_unhandled_api_error(
    aiohappyeyeballs_start_connection,
) -> None:
    """Verify finish_connect re-wraps exceptions as UnhandledAPIError."""

    cli = APIClient("127.0.0.1", 1234, None)
    with patch("aioesphomeapi.client.APIConnection", PatchableAPIConnection):
        await cli.start_resolve_host()
        await cli.start_connection()

    with (
        patch.object(
            cli._connection,
            "send_messages_await_response_complex",
            side_effect=Exception("foo"),
        ),
        pytest.raises(UnhandledAPIConnectionError, match="foo"),
    ):
        await cli.finish_connection(False)


async def test_connection_released_if_connecting_is_cancelled() -> None:
    """Verify connection is unset if connecting is cancelled."""
    cli = APIClient("127.0.0.1", 1234, None)
    asyncio.get_running_loop()

    async def _start_connection_with_delay(*args, **kwargs):
        await asyncio.sleep(1)
        mock_socket = create_autospec(socket.socket, spec_set=True, instance=True)
        mock_socket.getpeername.return_value = ("4.3.3.3", 323)
        return mock_socket

    with patch(
        "aioesphomeapi.connection.aiohappyeyeballs.start_connection",
        _start_connection_with_delay,
    ):
        await cli.start_resolve_host()
        start_task = asyncio.create_task(cli.start_connection())
        await asyncio.sleep(0)
        assert cli._connection is not None

    start_task.cancel()
    with contextlib.suppress(BaseException):
        await start_task
    assert cli._connection is None

    async def _start_connection_without_delay(*args, **kwargs):
        mock_socket = create_autospec(socket.socket, spec_set=True, instance=True)
        mock_socket.getpeername.return_value = ("4.3.3.3", 323)
        return mock_socket

    with (
        patch("aioesphomeapi.client.APIConnection", PatchableAPIConnection),
        patch(
            "aioesphomeapi.connection.aiohappyeyeballs.start_connection",
            _start_connection_without_delay,
        ),
    ):
        await cli.start_resolve_host()
        await cli.start_connection()
        await asyncio.sleep(0)

    assert cli._connection is not None
    task = asyncio.create_task(cli.finish_connection(False))
    await asyncio.sleep(0)
    task.cancel()
    with contextlib.suppress(BaseException):
        await task
    assert cli._connection is None


async def test_request_while_handshaking() -> None:
    """Test trying a request while handshaking raises."""

    cli = PatchableAPIClient("127.0.0.1", 1234, None)
    with (
        patch(
            "aioesphomeapi.connection.aiohappyeyeballs.start_connection",
            side_effect=partial(asyncio.sleep, 1),
        ),
        patch.object(cli, "finish_connection"),
    ):
        connect_task = asyncio.create_task(cli.connect())

    await asyncio.sleep(0)
    with pytest.raises(
        APIConnectionError, match="Authenticated connection not ready yet"
    ):
        await cli.device_info()

    connect_task.cancel()
    await asyncio.sleep(0)


async def test_connect_while_already_connected(auth_client: APIClient) -> None:
    """Test connecting while already connected raises."""
    with pytest.raises(APIConnectionError):
        await auth_client.start_resolve_host()


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


async def test_subscribe_states(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_state = MagicMock()
    auth_client.subscribe_states(on_state)
    on_state.assert_not_called()

    await send(BinarySensorStateResponse())
    on_state.assert_called_once_with(BinarySensorState())


async def test_subscribe_states_camera(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_state = MagicMock()
    auth_client.subscribe_states(on_state)
    await send(CameraImageResponse(key=1, data=b"asdf"))
    on_state.assert_not_called()

    await send(CameraImageResponse(key=1, data=b"qwer", done=True))
    on_state.assert_called_once_with(CameraState(key=1, data=b"asdfqwer"))


async def test_subscribe_states_camera_with_device_id(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_state = MagicMock()
    auth_client.subscribe_states(on_state)

    # Test with device_id=0 (default)
    await send(CameraImageResponse(key=1, data=b"asdf", device_id=0))
    on_state.assert_not_called()

    await send(CameraImageResponse(key=1, data=b"qwer", done=True, device_id=0))
    on_state.assert_called_once_with(CameraState(key=1, data=b"asdfqwer", device_id=0))

    on_state.reset_mock()

    # Test with device_id=5
    await send(CameraImageResponse(key=2, data=b"test", device_id=5))
    on_state.assert_not_called()

    await send(CameraImageResponse(key=2, data=b"data", done=True, device_id=5))
    on_state.assert_called_once_with(CameraState(key=2, data=b"testdata", device_id=5))


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

    auth_client.cover_command(**cmd)
    send.assert_called_once_with(CoverCommandRequest(**req))


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

    auth_client.cover_command(**cmd)
    send.assert_called_once_with(CoverCommandRequest(**req))


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
        (
            dict(key=1, preset_mode="auto"),
            dict(key=1, has_preset_mode=True, preset_mode="auto"),
        ),
    ],
)
async def test_fan_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    auth_client.fan_command(**cmd)
    send.assert_called_once_with(FanCommandRequest(**req))


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

    auth_client.light_command(**cmd)
    send.assert_called_once_with(LightCommandRequest(**req))


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

    auth_client.switch_command(**cmd)
    send.assert_called_once_with(SwitchCommandRequest(**req))


@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, preset=ClimatePreset.HOME),
            dict(key=1, unused_has_legacy_away=True, unused_legacy_away=False),
        ),
        (
            dict(key=1, preset=ClimatePreset.AWAY),
            dict(key=1, unused_has_legacy_away=True, unused_legacy_away=True),
        ),
    ],
)
async def test_climate_command_legacy(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)
    patch_api_version(auth_client, APIVersion(1, 4))

    auth_client.climate_command(**cmd)
    send.assert_called_once_with(ClimateCommandRequest(**req))


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
        (
            dict(key=1, target_humidity=60.0),
            dict(key=1, has_target_humidity=True, target_humidity=60.0),
        ),
    ],
)
async def test_climate_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)
    patch_api_version(auth_client, APIVersion(1, 5))

    auth_client.climate_command(**cmd)
    send.assert_called_once_with(ClimateCommandRequest(**req))


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

    auth_client.number_command(**cmd)
    send.assert_called_once_with(NumberCommandRequest(**req))


@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, year=2024, month=2, day=29),
            dict(key=1, year=2024, month=2, day=29),
        ),
        (
            dict(key=1, year=2000, month=6, day=10),
            dict(key=1, year=2000, month=6, day=10),
        ),
    ],
)
async def test_date_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    auth_client.date_command(**cmd)
    send.assert_called_once_with(DateCommandRequest(**req))


# Test time command


@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, hour=12, minute=30, second=30),
            dict(key=1, hour=12, minute=30, second=30),
        ),
        (
            dict(key=1, hour=0, minute=0, second=0),
            dict(key=1, hour=0, minute=0, second=0),
        ),
    ],
)
async def test_time_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    auth_client.time_command(**cmd)
    send.assert_called_once_with(TimeCommandRequest(**req))


# Test date_time command


@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, epoch_seconds=1735648230),
            dict(key=1, epoch_seconds=1735648230),
        ),
        (
            dict(key=1, epoch_seconds=1735689600),
            dict(key=1, epoch_seconds=1735689600),
        ),
    ],
)
async def test_datetime_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    auth_client.datetime_command(**cmd)
    send.assert_called_once_with(DateTimeCommandRequest(**req))


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

    auth_client.lock_command(**cmd)
    send.assert_called_once_with(LockCommandRequest(**req))


@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1), dict(key=1)),
        (dict(key=1, position=1.0), dict(key=1, position=1.0, has_position=True)),
        (dict(key=1, position=0.0), dict(key=1, position=0.0, has_position=True)),
        (dict(key=1, stop=True), dict(key=1, stop=True)),
    ],
)
async def test_valve_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    auth_client.valve_command(**cmd)
    send.assert_called_once_with(ValveCommandRequest(**req))


@pytest.mark.parametrize(
    "cmd, req",
    [
        (dict(key=1), dict(key=1)),
        (dict(key=1, position=0.5), dict(key=1, has_position=True, position=0.5)),
        (dict(key=1, position=0.0), dict(key=1, has_position=True, position=0.0)),
        (dict(key=1, stop=True), dict(key=1, stop=True)),
        (
            dict(key=1, position=1.0),
            dict(key=1, has_position=True, position=1.0),
        ),
    ],
)
async def test_valve_command_version_1_1(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)
    patch_api_version(auth_client, APIVersion(1, 1))

    auth_client.valve_command(**cmd)
    send.assert_called_once_with(ValveCommandRequest(**req))


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

    auth_client.select_command(**cmd)
    send.assert_called_once_with(SelectCommandRequest(**req))


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
        (
            dict(key=1, media_url="http://example.com", announcement=True),
            dict(
                key=1,
                has_media_url=True,
                media_url="http://example.com",
                has_announcement=True,
                announcement=True,
            ),
        ),
    ],
)
async def test_media_player_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    auth_client.media_player_command(**cmd)
    send.assert_called_once_with(MediaPlayerCommandRequest(**req))


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

    auth_client.button_command(**cmd)
    send.assert_called_once_with(ButtonCommandRequest(**req))


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

    auth_client.siren_command(**cmd)
    send.assert_called_once_with(SirenCommandRequest(**req))


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
        auth_client.execute_service(service, data={})

    auth_client.execute_service(
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
    auth_client.execute_service(
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
    auth_client.execute_service(
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


async def test_request_single_image(auth_client: APIClient) -> None:
    send = patch_send(auth_client)

    auth_client.request_single_image()
    send.assert_called_once_with(CameraImageRequest(single=True, stream=False))


async def test_request_image_stream(auth_client: APIClient) -> None:
    send = patch_send(auth_client)

    auth_client.request_image_stream()
    send.assert_called_once_with(CameraImageRequest(single=False, stream=True))


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

    auth_client.alarm_control_panel_command(**cmd)
    send.assert_called_once_with(AlarmControlPanelCommandRequest(**req))


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

    auth_client.text_command(**cmd)
    send.assert_called_once_with(TextCommandRequest(**req))


@pytest.mark.parametrize(
    "cmd, req",
    [
        (
            dict(key=1, command=UpdateCommand.INSTALL),
            dict(key=1, command=UpdateCommand.INSTALL),
        ),
        (
            dict(key=1, command=UpdateCommand.CHECK),
            dict(key=1, command=UpdateCommand.CHECK),
        ),
    ],
)
async def test_update_command(
    auth_client: APIClient, cmd: dict[str, Any], req: dict[str, Any]
) -> None:
    send = patch_send(auth_client)

    auth_client.update_command(**cmd)
    send.assert_called_once_with(UpdateCommandRequest(**req))


async def test_set_cached_name_if_unset_subclassed_string():
    """Test set_cached_name_if_unset with a subclassed string."""
    cli = PatchableAPIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="mydevice",
    )
    cli.set_cached_name_if_unset(Estr("mydevice"))
    assert cli.log_name == "mydevice @ 127.0.0.1"


async def test_noise_psk_handles_subclassed_string():
    """Test that the noise_psk gets converted to a string."""
    cli = PatchableAPIClient(
        address=Estr("127.0.0.1"),
        port=6052,
        password=None,
        noise_psk=Estr("QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="),
        expected_name=Estr("mydevice"),
    )
    # Make sure its not a subclassed string
    assert type(cli._params.noise_psk) is str
    assert type(cli._params.addresses[0]) is str
    assert type(cli._params.expected_name) is str

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection"),
    ):
        await rl.start()
        for _ in range(3):
            await asyncio.sleep(0)

    rl.stop_callback()
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_no_noise_psk():
    """Test not using a noise_psk."""
    cli = APIClient(
        address=Estr("127.0.0.1"),
        port=6052,
        password=None,
        noise_psk=None,
        expected_name=Estr("mydevice"),
    )
    # Make sure its not a subclassed string
    assert cli._params.noise_psk is None
    assert type(cli._params.addresses[0]) is str
    assert type(cli._params.expected_name) is str


async def test_empty_noise_psk_or_expected_name():
    """Test an empty noise_psk is treated as None."""
    cli = APIClient(
        address=Estr("127.0.0.1"),
        port=6052,
        password=None,
        noise_psk="",
        expected_name="",
    )
    assert cli._params.noise_psk is None
    assert type(cli._params.addresses[0]) is str
    assert cli._params.expected_name is None


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


async def test_bluetooth_pair(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_device_pair."""
    client, connection, transport, protocol = api_client
    pair_task = asyncio.create_task(client.bluetooth_device_pair(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDevicePairingResponse(address=4567)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    assert not pair_task.done()
    response: message.Message = BluetoothDevicePairingResponse(address=1234)
    mock_data_received(protocol, generate_plaintext_packet(response))
    await pair_task


async def test_bluetooth_pair_connection_drops(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test connection drop during bluetooth_device_pair."""
    client, connection, transport, protocol = api_client
    pair_task = asyncio.create_task(client.bluetooth_device_pair(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, error=13
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    message = (
        "Peripheral 00:00:00:00:04:D2 changed connection status while waiting"
        " for BluetoothDevicePairingResponse: Invalid attribute length"
    )
    with pytest.raises(BluetoothConnectionDroppedError, match=message):
        await pair_task


async def test_bluetooth_unpair_connection_drops(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test connection drop during bluetooth_device_unpair."""
    client, connection, transport, protocol = api_client
    pair_task = asyncio.create_task(client.bluetooth_device_unpair(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, error=13
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    message = (
        "Peripheral 00:00:00:00:04:D2 changed connection status while waiting"
        " for BluetoothDeviceUnpairingResponse: Invalid attribute length"
    )
    with pytest.raises(BluetoothConnectionDroppedError, match=message):
        await pair_task


async def test_bluetooth_clear_cache_connection_drops(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test connection drop during bluetooth_device_clear_cache."""
    client, connection, transport, protocol = api_client
    pair_task = asyncio.create_task(client.bluetooth_device_clear_cache(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, error=13
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    message = (
        "Peripheral 00:00:00:00:04:D2 changed connection status while waiting"
        " for BluetoothDeviceClearCacheResponse: Invalid attribute length"
    )
    with pytest.raises(BluetoothConnectionDroppedError, match=message):
        await pair_task


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


async def test_device_info(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test fetching device info."""
    client, connection, transport, protocol = api_client
    assert client.log_name == "fake @ 10.0.0.512"
    device_info_task = asyncio.create_task(client.device_info())
    await asyncio.sleep(0)
    response: message.Message = DeviceInfoResponse(
        name="realname",
        friendly_name="My Device",
        has_deep_sleep=True,
        mac_address="AA:BB:CC:DD:EE:FB",
        bluetooth_mac_address="AA:BB:CC:DD:EE:FF",
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    device_info = await device_info_task
    assert device_info.name == "realname"
    assert device_info.friendly_name == "My Device"
    assert device_info.has_deep_sleep
    assert device_info.mac_address == "AA:BB:CC:DD:EE:FB"
    assert device_info.bluetooth_mac_address == "AA:BB:CC:DD:EE:FF"
    assert client.log_name == "realname @ 10.0.0.512"
    disconnect_task = asyncio.create_task(client.disconnect())
    await asyncio.sleep(0)
    response: message.Message = DisconnectResponse()
    mock_data_received(protocol, generate_plaintext_packet(response))
    await disconnect_task
    with pytest.raises(APIConnectionError, match="Not connected"):
        await client.device_info()


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


async def test_bluetooth_gatt_read_connection_drops(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test connection drop during bluetooth_gatt_read."""
    client, connection, transport, protocol = api_client
    read_task = asyncio.create_task(client.bluetooth_gatt_read(1234, 1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, error=13
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    message = (
        "Peripheral 00:00:00:00:04:D2 changed connection status while waiting"
        " for BluetoothGATTReadResponse, BluetoothGATTErrorResponse: Invalid attribute length"
    )
    with pytest.raises(BluetoothConnectionDroppedError, match=message):
        await read_task


async def test_bluetooth_gatt_read_error(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_read that errors."""
    client, connection, transport, protocol = api_client
    read_task = asyncio.create_task(client.bluetooth_gatt_read(1234, 1234))
    await asyncio.sleep(0)
    error_response: message.Message = BluetoothGATTErrorResponse(
        address=1234, handle=1234
    )
    mock_data_received(protocol, generate_plaintext_packet(error_response))
    with pytest.raises(BluetoothGATTAPIError):
        await read_task


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


async def test_bluetooth_gatt_write_connection_drops(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test connection drop during bluetooth_gatt_read."""
    client, connection, transport, protocol = api_client
    write_task = asyncio.create_task(
        client.bluetooth_gatt_write(1234, 1234, b"1234", True)
    )
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, error=13
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    message = (
        "Peripheral 00:00:00:00:04:D2 changed connection status while waiting"
        " for BluetoothGATTWriteResponse, BluetoothGATTErrorResponse: Invalid attribute length"
    )
    with pytest.raises(BluetoothConnectionDroppedError, match=message):
        await write_task


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
    assert transport.mock_calls[0][1][0] == [
        b"\x00",
        b"\x0c",
        b"K",
        b'\x08\xd2\t\x10\xd2\t"\x041234',
    ]

    with pytest.raises(TimeoutAPIError, match="BluetoothGATTWriteResponse"):
        await client.bluetooth_gatt_write(1234, 1234, b"1234", True, timeout=0)


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
    assert transport.mock_calls[0][1][0] == [
        b"\x00",
        b"\x0c",
        b"M",
        b"\x08\xd2\t\x10\xd2\t\x1a\x041234",
    ]

    with pytest.raises(TimeoutAPIError, match="BluetoothGATTWriteResponse"):
        await client.bluetooth_gatt_write_descriptor(1234, 1234, b"1234", timeout=0)


async def test_bluetooth_gatt_get_services_connection_drops(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test connection drop during bluetooth_gatt_get_services."""
    client, connection, transport, protocol = api_client
    services_task = asyncio.create_task(client.bluetooth_gatt_get_services(1234))
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, error=13
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    message = (
        "Peripheral 00:00:00:00:04:D2 changed connection status while waiting"
        " for BluetoothGATTGetServicesResponse, BluetoothGATTGetServicesDoneResponse, "
        "BluetoothGATTErrorResponse: Invalid attribute length"
    )
    with pytest.raises(BluetoothConnectionDroppedError, match=message):
        await services_task


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
    response: message.Message = BluetoothGATTGetServicesResponse(
        address=1234, services=[service1]
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    done_response: message.Message = BluetoothGATTGetServicesDoneResponse(address=1234)
    mock_data_received(protocol, generate_plaintext_packet(done_response))

    services = await services_task
    service = BluetoothGATTServiceModel.from_pb(service1)
    assert services == ESPHomeBluetoothGATTServices(
        address=1234,
        services=[service],
    )


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


async def test_bluetooth_gatt_start_notify_connection_drops(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test connection drop during bluetooth_gatt_start_notify."""
    client, connection, transport, protocol = api_client
    notify_task = asyncio.create_task(
        client.bluetooth_gatt_start_notify(1234, 1, lambda handle, data: None)
    )
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, error=13
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    message = (
        "Peripheral 00:00:00:00:04:D2 changed connection status while waiting"
        " for BluetoothGATTNotifyResponse, BluetoothGATTErrorResponse: Invalid attribute length"
    )
    with pytest.raises(BluetoothConnectionDroppedError, match=message):
        await notify_task


async def test_bluetooth_gatt_start_notify(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_gatt_start_notify."""
    client, connection, transport, protocol = api_client
    notifies = []

    handlers_before = len(list(itertools.chain(*connection._message_handlers.values())))

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
        len(list(itertools.chain(*connection._message_handlers.values())))
        == handlers_before
    )
    # Ensure abort callback is a no-op after cancel
    # and doesn't raise
    abort_cb()
    await client.disconnect(force=True)
    # Ensure abort callback is a no-op after disconnect
    # and does not raise
    await cancel_cb()


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

    handlers_before = len(list(itertools.chain(*connection._message_handlers.values())))

    with (
        patch.object(
            connection,
            "send_messages_await_response_complex",
            side_effect=APIConnectionError,
        ),
        pytest.raises(APIConnectionError),
    ):
        await client.bluetooth_gatt_start_notify(1234, 1, on_bluetooth_gatt_notify)

    assert (
        len(list(itertools.chain(*connection._message_handlers.values())))
        == handlers_before
    )


async def test_bluetooth_gatt_notify_callback_raises(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that exceptions in bluetooth gatt notify callbacks are caught."""
    client, connection, transport, protocol = api_client

    def on_bluetooth_gatt_notify(handle: int, data: bytearray) -> None:
        raise ValueError("Test exception in notify callback")

    notify_task = asyncio.create_task(
        client.bluetooth_gatt_start_notify(1234, 1, on_bluetooth_gatt_notify)
    )
    await asyncio.sleep(0)
    notify_response: message.Message = BluetoothGATTNotifyResponse(
        address=1234, handle=1
    )
    mock_data_received(protocol, generate_plaintext_packet(notify_response))
    await notify_task

    # Clear any logs from the notify setup
    caplog.clear()

    # Send data that will trigger the exception
    data_response: message.Message = BluetoothGATTNotifyDataResponse(
        address=1234, handle=1, data=b"test_data"
    )
    mock_data_received(protocol, generate_plaintext_packet(data_response))
    await asyncio.sleep(0)

    # Verify the exception was caught and logged
    assert "Unexpected error in Bluetooth GATT notify callback" in caplog.text
    assert "ValueError: Test exception in notify callback" in caplog.text
    assert "address 1234, handle 1" in caplog.text

    # Verify the connection is still alive
    assert connection.is_connected


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

    unsub = client.subscribe_bluetooth_le_advertisements(on_bluetooth_le_advertisements)
    await asyncio.sleep(0)
    response: message.Message = BluetoothLEAdvertisementResponse(
        address=1234,
        name=b"mydevice",
        rssi=-50,
        service_uuids=["1234"],
        service_data=[
            BluetoothServiceData(
                uuid="1234",
                data=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
        ],
        manufacturer_data=[
            BluetoothServiceData(
                uuid="1234",
                data=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
        ],
        address_type=1,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    assert advs == [
        BluetoothLEAdvertisement(
            address=1234,
            name="mydevice",
            rssi=-50,
            service_uuids=["000034-0000-1000-8000-00805f9b34fb"],
            manufacturer_data={
                4660: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            },
            service_data={
                "000034-0000-1000-8000-00805f9b34fb": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            },
            address_type=1,
        )
    ]
    advs.clear()
    response: message.Message = BluetoothLEAdvertisementResponse(
        address=1234,
        name=b"mydevice",
        rssi=-50,
        service_uuids=[],
        service_data=[],
        manufacturer_data=[],
        address_type=1,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    assert advs == [
        BluetoothLEAdvertisement(
            address=1234,
            name="mydevice",
            rssi=-50,
            service_uuids=[],
            manufacturer_data={},
            service_data={},
            address_type=1,
        )
    ]
    advs.clear()
    response: message.Message = BluetoothLEAdvertisementResponse(
        address=1234,
        name=b"mydevice",
        rssi=-50,
        service_uuids=["1234"],
        service_data=[
            BluetoothServiceData(
                uuid="1234",
                legacy_data=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
        ],
        manufacturer_data=[
            BluetoothServiceData(
                uuid="1234",
                legacy_data=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
        ],
        address_type=1,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    assert advs == [
        BluetoothLEAdvertisement(
            address=1234,
            name="mydevice",
            rssi=-50,
            service_uuids=["000034-0000-1000-8000-00805f9b34fb"],
            manufacturer_data={
                4660: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            },
            service_data={
                "000034-0000-1000-8000-00805f9b34fb": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            },
            address_type=1,
        )
    ]
    unsub()


async def test_subscribe_bluetooth_le_raw_advertisements(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_bluetooth_le_raw_advertisements."""
    client, connection, transport, protocol = api_client
    adv_groups = []

    def on_raw_bluetooth_le_advertisements(
        advs: BluetoothLERawAdvertisementsResponse,
    ) -> None:
        adv_groups.append(advs.advertisements)

    unsub = client.subscribe_bluetooth_le_raw_advertisements(
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


async def test_subscribe_bluetooth_connections_free(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_bluetooth_connections_free."""
    client, connection, transport, protocol = api_client
    connections = []

    def on_bluetooth_connections_free(
        free: int, limit: int, allocated: list[int]
    ) -> None:
        connections.append((free, limit, allocated))

    unsub = client.subscribe_bluetooth_connections_free(on_bluetooth_connections_free)
    await asyncio.sleep(0)
    response: message.Message = BluetoothConnectionsFreeResponse(
        free=2, limit=3, allocated=[1234, 5678]
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    assert connections == [(2, 3, [1234, 5678])]
    unsub()


async def test_subscribe_home_assistant_states(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_home_assistant_states."""
    client, connection, transport, protocol = api_client
    states = []
    requests = []

    def on_subscribe_home_assistant_states(
        entity_id: str, attribute: str | None
    ) -> None:
        states.append((entity_id, attribute))

    def on_request_home_assistant_state(entity_id: str, attribute: str | None) -> None:
        requests.append((entity_id, attribute))

    client.subscribe_home_assistant_states(
        on_subscribe_home_assistant_states,
        on_request_home_assistant_state,
    )

    await asyncio.sleep(0)

    response: message.Message = SubscribeHomeAssistantStateResponse(
        entity_id="sensor.red", attribute="any"
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    response: message.Message = SubscribeHomeAssistantStateResponse(
        entity_id="sensor.green"
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    response: message.Message = SubscribeHomeAssistantStateResponse(
        entity_id="sensor.blue", attribute="any", once=True
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    response: message.Message = SubscribeHomeAssistantStateResponse(
        entity_id="sensor.white", once=True
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    assert states == [("sensor.red", "any"), ("sensor.green", "")]
    assert requests == [("sensor.blue", "any"), ("sensor.white", "")]


async def test_subscribe_logs(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_logs = MagicMock()
    cancel = auth_client.subscribe_logs(on_logs)
    log_msg = SubscribeLogsResponse(level=1, message=b"asdf")
    await send(log_msg)
    on_logs.assert_called_with(log_msg)
    on_logs.reset_mock()
    cancel()
    log_msg = SubscribeLogsResponse(level=1, message=b"asdf")
    await send(log_msg)
    on_logs.assert_not_called()
    on_logs.reset_mock()


async def test_send_home_assistant_state(auth_client: APIClient) -> None:
    send = patch_send(auth_client)
    auth_client.send_home_assistant_state("binary_sensor.bla", None, "on")
    send.assert_called_once_with(
        HomeAssistantStateResponse(
            entity_id="binary_sensor.bla", state="on", attribute=None
        )
    )


async def test_subscribe_service_calls(auth_client: APIClient) -> None:
    send = patch_response_callback(auth_client)
    on_service_call = MagicMock()
    auth_client.subscribe_service_calls(on_service_call)
    service_msg = HomeassistantServiceResponse(service="bob")
    await send(service_msg)
    on_service_call.assert_called_with(HomeassistantServiceCall.from_pb(service_msg))


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
    assert client.log_name == "fake @ 10.0.0.512"
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


async def test_force_disconnect(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test force disconnect can be called multiple times."""
    client, connection, transport, protocol = api_client
    assert connection.is_connected is True
    assert connection.on_stop is not None
    await client.disconnect(force=True)
    assert client._connection is None
    assert connection.is_connected is False
    await client.disconnect(force=False)
    assert connection.is_connected is False


@pytest.mark.parametrize(
    ("has_cache", "feature_flags", "method"),
    [
        (False, BluetoothProxyFeature(0), BluetoothDeviceRequestType.CONNECT),
        (
            False,
            BluetoothProxyFeature.REMOTE_CACHING,
            BluetoothDeviceRequestType.CONNECT_V3_WITHOUT_CACHE,
        ),
        (
            True,
            BluetoothProxyFeature.REMOTE_CACHING,
            BluetoothDeviceRequestType.CONNECT_V3_WITH_CACHE,
        ),
    ],
)
async def test_bluetooth_device_connect(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
    has_cache: bool,
    feature_flags: BluetoothProxyFeature,
    method: BluetoothDeviceRequestType,
) -> None:
    """Test bluetooth_device_connect."""
    client, connection, transport, protocol = api_client
    states = []

    def on_bluetooth_connection_state(connected: bool, mtu: int, error: int) -> None:
        states.append((connected, mtu, error))

    connect_task = asyncio.create_task(
        client.bluetooth_device_connect(
            1234,
            on_bluetooth_connection_state,
            timeout=1,
            feature_flags=feature_flags,
            has_cache=has_cache,
            disconnect_timeout=1,
            address_type=1,
        )
    )
    await asyncio.sleep(0)
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=True, mtu=23, error=0
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    cancel = await connect_task
    assert states == [(True, 23, 0)]
    transport.writelines.assert_called_once_with(
        generate_split_plaintext_packet(
            BluetoothDeviceRequest(
                address=1234,
                request_type=method,
                has_address_type=True,
                address_type=1,
            ),
        )
    )
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, mtu=23, error=7
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    assert states == [(True, 23, 0), (False, 23, 7)]
    cancel()

    # After cancel, no more messages should called back
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, mtu=23, error=8
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    assert states == [(True, 23, 0), (False, 23, 7)]

    # Make sure cancel is safe to call again
    cancel()

    await client.disconnect(force=True)
    await asyncio.sleep(0)
    assert not client._connection
    # Make sure cancel is safe to call after disconnect
    cancel()


async def test_bluetooth_device_connect_and_disconnect_times_out(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_device_connect and disconnect times out."""
    client, connection, transport, protocol = api_client
    states = []

    def on_bluetooth_connection_state(connected: bool, mtu: int, error: int) -> None:
        states.append((connected, mtu, error))

    connect_task = asyncio.create_task(
        client.bluetooth_device_connect(
            1234,
            on_bluetooth_connection_state,
            timeout=0,
            feature_flags=0,
            has_cache=True,
            disconnect_timeout=0,
            address_type=1,
        )
    )
    with pytest.raises(TimeoutAPIError):
        await connect_task
    assert states == []


async def test_bluetooth_device_connect_times_out_disconnect_ok(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_device_connect and disconnect times out."""
    client, connection, transport, protocol = api_client
    states = []

    def on_bluetooth_connection_state(connected: bool, mtu: int, error: int) -> None:
        states.append((connected, mtu, error))

    connect_task = asyncio.create_task(
        client.bluetooth_device_connect(
            1234,
            on_bluetooth_connection_state,
            timeout=0,
            feature_flags=0,
            has_cache=True,
            disconnect_timeout=1,
            address_type=1,
        )
    )
    await asyncio.sleep(0)
    # The connect request should be written
    assert len(transport.writelines.mock_calls) == 1
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    # Now that we timed out, the disconnect
    # request should be written
    assert len(transport.writelines.mock_calls) == 2
    response: message.Message = BluetoothDeviceConnectionResponse(
        address=1234, connected=False, mtu=23, error=8
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    with pytest.raises(TimeoutAPIError):
        await connect_task
    assert states == []


async def test_bluetooth_device_connect_cancelled(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_device_connect handles cancellation."""
    client, connection, transport, protocol = api_client
    states = []

    handlers_before = len(list(itertools.chain(*connection._message_handlers.values())))

    def on_bluetooth_connection_state(connected: bool, mtu: int, error: int) -> None:
        states.append((connected, mtu, error))

    connect_task = asyncio.create_task(
        client.bluetooth_device_connect(
            1234,
            on_bluetooth_connection_state,
            timeout=10,
            feature_flags=0,
            has_cache=True,
            disconnect_timeout=10,
            address_type=1,
        )
    )
    await asyncio.sleep(0)
    # The connect request should be written
    assert len(transport.writelines.mock_calls) == 1
    connect_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await connect_task
    assert states == []

    # Ensure the disconnect request is written
    assert len(transport.writelines.mock_calls) == 2
    req = BluetoothDeviceRequest(
        address=1234, request_type=BluetoothDeviceRequestType.DISCONNECT
    ).SerializeToString()
    assert transport.writelines.mock_calls[-1] == call([b"\x00", b"\x05", b"D", req])

    handlers_after = len(list(itertools.chain(*connection._message_handlers.values())))
    # Make sure we do not leak message handlers
    assert handlers_after == handlers_before


async def test_send_voice_assistant_event(auth_client: APIClient) -> None:
    send = patch_send(auth_client)

    auth_client.send_voice_assistant_event(
        VoiceAssistantEventModelType.VOICE_ASSISTANT_ERROR,
        {"error": "error", "ok": "ok"},
    )
    send.assert_called_once_with(
        VoiceAssistantEventResponse(
            event_type=VoiceAssistantEventModelType.VOICE_ASSISTANT_ERROR.value,
            data=[
                VoiceAssistantEventData(name="error", value="error"),
                VoiceAssistantEventData(name="ok", value="ok"),
            ],
        )
    )

    send.reset_mock()
    auth_client.send_voice_assistant_event(
        VoiceAssistantEventModelType.VOICE_ASSISTANT_ERROR, None
    )
    send.assert_called_once_with(
        VoiceAssistantEventResponse(
            event_type=VoiceAssistantEventModelType.VOICE_ASSISTANT_ERROR.value,
            data=[],
        )
    )


async def test_subscribe_voice_assistant(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_voice_assistant."""
    client, connection, transport, protocol = api_client
    send = patch_send(client)
    starts = []
    stops = []
    aborts = []

    async def handle_start(
        conversation_id: str,
        flags: int,
        audio_settings: VoiceAssistantAudioSettings,
        wake_word_phrase: str | None,
    ) -> int | None:
        starts.append((conversation_id, flags, audio_settings, wake_word_phrase))
        return 42

    async def handle_stop(abort: bool) -> None:
        if abort:
            aborts.append(True)
        else:
            stops.append(True)

    unsub = client.subscribe_voice_assistant(
        handle_start=handle_start, handle_stop=handle_stop
    )
    send.assert_called_once_with(SubscribeVoiceAssistantRequest(subscribe=True))
    send.reset_mock()
    audio_settings = VoiceAssistantAudioSettings(
        noise_suppression_level=42,
        auto_gain=42,
        volume_multiplier=42,
    )
    response: message.Message = VoiceAssistantRequest(
        conversation_id="theone",
        start=True,
        flags=42,
        audio_settings=audio_settings,
        wake_word_phrase="okay nabu",
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert starts == [
        (
            "theone",
            42,
            VoiceAssistantAudioSettingsModel(
                noise_suppression_level=42,
                auto_gain=42,
                volume_multiplier=42,
            ),
            "okay nabu",
        )
    ]
    assert not stops
    assert not aborts
    send.assert_called_once_with(VoiceAssistantResponse(port=42))
    send.reset_mock()
    response: message.Message = VoiceAssistantRequest(
        conversation_id="theone",
        start=False,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    assert not stops
    assert aborts == [True]
    send.reset_mock()
    unsub()
    send.assert_called_once_with(SubscribeVoiceAssistantRequest(subscribe=False))
    send.reset_mock()
    await client.disconnect(force=True)
    # Ensure abort callback is a no-op after disconnect
    # and does not raise
    unsub()
    assert len(send.mock_calls) == 0


async def test_subscribe_voice_assistant_failure(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_voice_assistant failure."""
    client, connection, transport, protocol = api_client
    send = patch_send(client)
    starts = []
    stops = []
    aborts = []

    async def handle_start(
        conversation_id: str,
        flags: int,
        audio_settings: VoiceAssistantAudioSettings,
        wake_word_phrase: str | None,
    ) -> int | None:
        starts.append((conversation_id, flags, audio_settings, wake_word_phrase))
        # Return None to indicate failure
        return None

    async def handle_stop(abort: bool) -> None:
        if abort:
            aborts.append(True)
        else:
            stops.append(True)

    unsub = client.subscribe_voice_assistant(
        handle_start=handle_start, handle_stop=handle_stop
    )
    send.assert_called_once_with(SubscribeVoiceAssistantRequest(subscribe=True))
    send.reset_mock()
    audio_settings = VoiceAssistantAudioSettings(
        noise_suppression_level=42,
        auto_gain=42,
        volume_multiplier=42,
    )
    response: message.Message = VoiceAssistantRequest(
        conversation_id="theone",
        start=True,
        flags=42,
        audio_settings=audio_settings,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert starts == [
        (
            "theone",
            42,
            VoiceAssistantAudioSettingsModel(
                noise_suppression_level=42,
                auto_gain=42,
                volume_multiplier=42,
            ),
            None,
        )
    ]
    assert not stops
    assert not aborts
    send.assert_called_once_with(VoiceAssistantResponse(error=True))
    send.reset_mock()
    response: message.Message = VoiceAssistantRequest(
        conversation_id="theone",
        start=False,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    assert not stops
    assert aborts == [True]
    send.reset_mock()
    unsub()
    send.assert_called_once_with(SubscribeVoiceAssistantRequest(subscribe=False))
    send.reset_mock()
    await client.disconnect(force=True)
    # Ensure abort callback is a no-op after disconnect
    # and does not raise
    unsub()
    assert len(send.mock_calls) == 0


async def test_subscribe_voice_assistant_cancels_long_running_handle_start(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_voice_assistant cancels long running tasks on unsub."""
    client, connection, transport, protocol = api_client
    send = patch_send(client)
    starts = []
    stops = []
    aborts = []

    async def handle_start(
        conversation_id: str,
        flags: int,
        audio_settings: VoiceAssistantAudioSettings,
        wake_word_phrase: str | None,
    ) -> int | None:
        starts.append((conversation_id, flags, audio_settings, wake_word_phrase))
        await asyncio.sleep(10)
        # Return None to indicate failure
        starts.append("never")
        return None

    async def handle_stop(abort: bool) -> None:
        if abort:
            aborts.append(True)
        else:
            stops.append(True)

    unsub = client.subscribe_voice_assistant(
        handle_start=handle_start, handle_stop=handle_stop
    )
    send.assert_called_once_with(SubscribeVoiceAssistantRequest(subscribe=True))
    send.reset_mock()
    audio_settings = VoiceAssistantAudioSettings(
        noise_suppression_level=42,
        auto_gain=42,
        volume_multiplier=42,
    )
    response: message.Message = VoiceAssistantRequest(
        conversation_id="theone",
        start=True,
        flags=42,
        audio_settings=audio_settings,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    unsub()
    await asyncio.sleep(0)
    assert not stops
    assert not aborts
    assert starts == [
        (
            "theone",
            42,
            VoiceAssistantAudioSettingsModel(
                noise_suppression_level=42,
                auto_gain=42,
                volume_multiplier=42,
            ),
            None,
        )
    ]


async def test_subscribe_voice_assistant_api_audio(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_voice_assistant."""
    client, connection, transport, protocol = api_client
    send = patch_send(client)
    starts = []
    stops = []
    aborts = []
    data_received = 0

    async def handle_start(
        conversation_id: str,
        flags: int,
        audio_settings: VoiceAssistantAudioSettings,
        wake_word_phrase: str | None,
    ) -> int | None:
        starts.append((conversation_id, flags, audio_settings, wake_word_phrase))
        return 0

    async def handle_stop(abort: bool) -> None:
        if abort:
            aborts.append(True)
        else:
            stops.append(True)

    async def handle_audio(data: bytes) -> None:
        nonlocal data_received
        data_received += len(data)

    unsub = client.subscribe_voice_assistant(
        handle_start=handle_start, handle_stop=handle_stop, handle_audio=handle_audio
    )
    send.assert_called_once_with(
        SubscribeVoiceAssistantRequest(subscribe=True, flags=4)
    )
    send.reset_mock()
    audio_settings = VoiceAssistantAudioSettings(
        noise_suppression_level=42,
        auto_gain=42,
        volume_multiplier=42,
    )
    response: message.Message = VoiceAssistantRequest(
        conversation_id="theone",
        start=True,
        flags=42,
        audio_settings=audio_settings,
        wake_word_phrase="okay nabu",
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert starts == [
        (
            "theone",
            42,
            VoiceAssistantAudioSettingsModel(
                noise_suppression_level=42,
                auto_gain=42,
                volume_multiplier=42,
            ),
            "okay nabu",
        )
    ]
    assert not stops
    assert not aborts
    send.assert_called_once_with(VoiceAssistantResponse(port=0))
    send.reset_mock()

    response: message.Message = VoiceAssistantAudio(
        data=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    assert data_received == 10

    response: message.Message = VoiceAssistantAudio(
        end=True,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    assert stops == [True]

    send.reset_mock()
    client.send_voice_assistant_audio(bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
    send.assert_called_once_with(
        VoiceAssistantAudio(data=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
    )

    response: message.Message = VoiceAssistantRequest(
        conversation_id="theone",
        start=False,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))
    await asyncio.sleep(0)
    assert stops == [True]
    assert aborts == [True]
    send.reset_mock()
    unsub()
    send.assert_called_once_with(SubscribeVoiceAssistantRequest(subscribe=False))
    send.reset_mock()
    await client.disconnect(force=True)
    # Ensure abort callback is a no-op after disconnect
    # and does not raise
    unsub()
    assert len(send.mock_calls) == 0


async def test_send_voice_assistant_timer_event(auth_client: APIClient) -> None:
    send = patch_send(auth_client)

    auth_client.send_voice_assistant_timer_event(
        VoiceAssistantTimerEventModelType.VOICE_ASSISTANT_TIMER_STARTED,
        timer_id="test",
        name="test",
        total_seconds=99,
        seconds_left=45,
        is_active=True,
    )

    send.assert_called_once_with(
        VoiceAssistantTimerEventResponse(
            event_type=VoiceAssistantTimerEventModelType.VOICE_ASSISTANT_TIMER_STARTED,
            timer_id="test",
            name="test",
            total_seconds=99,
            seconds_left=45,
            is_active=True,
        )
    )


async def test_send_voice_assistant_announcement_await_response(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    client, connection, _transport, protocol = api_client
    original_send_message = connection.send_message

    def send_message(msg):
        assert msg == VoiceAssistantAnnounceRequest(
            media_id="test-media-id", text="test-text"
        )
        original_send_message(msg)

    with patch.object(connection, "send_message", new=send_message):
        announcement_task = asyncio.create_task(
            client.send_voice_assistant_announcement_await_response(
                media_id="test-media-id", timeout=60.0, text="test-text"
            )
        )
        await asyncio.sleep(0)
        response: message.Message = VoiceAssistantAnnounceFinished(success=True)
        mock_data_received(protocol, generate_plaintext_packet(response))
        finished = await announcement_task
        assert isinstance(finished, VoiceAssistantAnnounceFinishedModel)


async def test_subscribe_voice_assistant_announcement_finished(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test subscribe_voice_assistant with handle_announcement_finished."""
    client, connection, transport, protocol = api_client
    send = patch_send(client)
    done = asyncio.Event()

    async def handle_start(
        conversation_id: str,
        flags: int,
        audio_settings: VoiceAssistantAudioSettings,
        wake_word_phrase: str | None,
    ) -> int | None:
        return 0

    async def handle_stop() -> None:
        pass

    async def handle_announcement_finished(
        finished: VoiceAssistantAnnounceFinishedModel,
    ) -> None:
        assert finished.success
        done.set()

    unsub = client.subscribe_voice_assistant(
        handle_start=handle_start,
        handle_stop=handle_stop,
        handle_announcement_finished=handle_announcement_finished,
    )
    send.assert_called_once_with(
        SubscribeVoiceAssistantRequest(subscribe=True, flags=0)
    )
    send.reset_mock()
    response: message.Message = VoiceAssistantAnnounceFinished(success=True)
    mock_data_received(protocol, generate_plaintext_packet(response))

    await asyncio.wait_for(done.wait(), 1)

    await client.disconnect(force=True)
    # Ensure abort callback is a no-op after disconnect
    # and does not raise
    unsub()
    assert len(send.mock_calls) == 0


async def test_get_voice_assistant_configuration(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    client, connection, _transport, protocol = api_client
    original_send_message = connection.send_message

    def send_message(msg):
        assert msg == VoiceAssistantConfigurationRequest()
        original_send_message(msg)

    with patch.object(connection, "send_message", new=send_message):
        config_task = asyncio.create_task(
            client.get_voice_assistant_configuration(timeout=1.0)
        )
        await asyncio.sleep(0)
        response: message.Message = VoiceAssistantConfigurationResponse(
            available_wake_words=[
                VoiceAssistantWakeWord(
                    id="1234",
                    wake_word="okay nabu",
                    trained_languages=["en"],
                )
            ],
            active_wake_words=["1234"],
            max_active_wake_words=1,
        )
        mock_data_received(protocol, generate_plaintext_packet(response))
        config = await config_task
        assert isinstance(config, VoiceAssistantConfigurationResponseModel)


async def test_set_voice_assistant_configuration(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    client, connection, _transport, protocol = api_client
    original_send_message = connection.send_message

    def send_message(msg):
        assert msg == VoiceAssistantSetConfiguration(active_wake_words=["1234"])
        original_send_message(msg)

    with patch.object(connection, "send_message", new=send_message):
        await client.set_voice_assistant_configuration(["1234"])


async def test_api_version_after_connection_closed(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test api version is None after connection close."""
    client, connection, transport, protocol = api_client
    assert client.api_version == APIVersion(1, 9)
    await client.disconnect(force=True)
    assert client.api_version is None


async def test_calls_after_connection_closed(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test calls after connection close should raise APIConnectionError."""
    client, connection, transport, protocol = api_client
    assert client.api_version == APIVersion(1, 9)
    await client.disconnect(force=True)
    assert client.api_version is None
    service = UserService(
        name="my_service",
        key=1,
        args=[],
    )
    with pytest.raises(APIConnectionError):
        client.execute_service(service, {})
    for method in (
        client.button_command,
        client.climate_command,
        client.cover_command,
        client.fan_command,
        client.light_command,
        client.valve_command,
        client.media_player_command,
        client.siren_command,
    ):
        with pytest.raises(APIConnectionError):
            await method(1)

    with pytest.raises(APIConnectionError):
        await client.alarm_control_panel_command(1, AlarmControlPanelCommand.ARM_HOME)

    with pytest.raises(APIConnectionError):
        await client.date_command(1, 1, 1, 1)

    with pytest.raises(APIConnectionError):
        await client.lock_command(1, LockCommand.LOCK)

    with pytest.raises(APIConnectionError):
        await client.number_command(1, 1)

    with pytest.raises(APIConnectionError):
        await client.select_command(1, "1")

    with pytest.raises(APIConnectionError):
        await client.switch_command(1, True)

    with pytest.raises(APIConnectionError):
        await client.text_command(1, "1")

    with pytest.raises(APIConnectionError):
        await client.update_command(1, True)


async def test_noise_encryption_set_key(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test set_noise_encryption_key."""
    client, connection, transport, protocol = api_client
    original_send_message = connection.send_message

    def send_message(msg):
        assert msg == NoiseEncryptionSetKeyRequest(key=b"1234")
        original_send_message(msg)

    with patch.object(connection, "send_message", new=send_message):
        set_task = asyncio.create_task(client.noise_encryption_set_key(b"1234"))
        await asyncio.sleep(0)
        response: message.Message = NoiseEncryptionSetKeyResponse(success=True)
        mock_data_received(protocol, generate_plaintext_packet(response))
        success = await set_task
        assert success is True


async def test_bluetooth_scanner_set_mode(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    """Test bluetooth_scanner_set_mode."""
    client, connection, transport, protocol = api_client
    send = patch_send(client)
    done = asyncio.Event()

    def _on_bluetooth_scanner_state(state: BluetoothScannerStateResponseModel) -> None:
        assert state.mode == BluetoothScannerModeModel.ACTIVE
        done.set()

    unsub = client.subscribe_bluetooth_scanner_state(_on_bluetooth_scanner_state)

    client.bluetooth_scanner_set_mode(BluetoothScannerModeModel.ACTIVE)

    send.assert_called_once_with(
        BluetoothScannerSetModeRequest(
            mode=BluetoothScannerMode.BLUETOOTH_SCANNER_MODE_ACTIVE
        )
    )
    send.reset_mock()

    response: message.Message = BluetoothScannerStateResponse(
        state=BluetoothScannerState.BLUETOOTH_SCANNER_STATE_RUNNING,
        mode=BluetoothScannerMode.BLUETOOTH_SCANNER_MODE_ACTIVE,
    )
    mock_data_received(protocol, generate_plaintext_packet(response))

    await asyncio.wait_for(done.wait(), 1)

    unsub()


@pytest.mark.parametrize(
    ("method_name", "method_args", "expected_request"),
    [
        # Test with device_id=0 (default)
        (
            "switch_command",
            {"key": 1, "state": True},
            SwitchCommandRequest(key=1, state=True, device_id=0),
        ),
        # Test with device_id=5
        (
            "switch_command",
            {"key": 1, "state": True, "device_id": 5},
            SwitchCommandRequest(key=1, state=True, device_id=5),
        ),
        # Button command
        ("button_command", {"key": 2}, ButtonCommandRequest(key=2, device_id=0)),
        (
            "button_command",
            {"key": 2, "device_id": 10},
            ButtonCommandRequest(key=2, device_id=10),
        ),
        # Number command
        (
            "number_command",
            {"key": 3, "state": 50.0},
            NumberCommandRequest(key=3, state=50.0, device_id=0),
        ),
        (
            "number_command",
            {"key": 3, "state": 50.0, "device_id": 15},
            NumberCommandRequest(key=3, state=50.0, device_id=15),
        ),
        # Select command
        (
            "select_command",
            {"key": 4, "state": "option1"},
            SelectCommandRequest(key=4, state="option1", device_id=0),
        ),
        (
            "select_command",
            {"key": 4, "state": "option1", "device_id": 20},
            SelectCommandRequest(key=4, state="option1", device_id=20),
        ),
        # Text command
        (
            "text_command",
            {"key": 5, "state": "hello"},
            TextCommandRequest(key=5, state="hello", device_id=0),
        ),
        (
            "text_command",
            {"key": 5, "state": "hello", "device_id": 25},
            TextCommandRequest(key=5, state="hello", device_id=25),
        ),
        # Date command
        (
            "date_command",
            {"key": 6, "year": 2024, "month": 1, "day": 1},
            DateCommandRequest(key=6, year=2024, month=1, day=1, device_id=0),
        ),
        (
            "date_command",
            {"key": 6, "year": 2024, "month": 1, "day": 1, "device_id": 30},
            DateCommandRequest(key=6, year=2024, month=1, day=1, device_id=30),
        ),
        # Time command
        (
            "time_command",
            {"key": 7, "hour": 12, "minute": 30, "second": 0},
            TimeCommandRequest(key=7, hour=12, minute=30, second=0, device_id=0),
        ),
        (
            "time_command",
            {"key": 7, "hour": 12, "minute": 30, "second": 0, "device_id": 35},
            TimeCommandRequest(key=7, hour=12, minute=30, second=0, device_id=35),
        ),
        # DateTime command
        (
            "datetime_command",
            {"key": 8, "epoch_seconds": 1234567890},
            DateTimeCommandRequest(key=8, epoch_seconds=1234567890, device_id=0),
        ),
        (
            "datetime_command",
            {"key": 8, "epoch_seconds": 1234567890, "device_id": 40},
            DateTimeCommandRequest(key=8, epoch_seconds=1234567890, device_id=40),
        ),
        # Update command
        (
            "update_command",
            {"key": 9, "command": UpdateCommand.INSTALL},
            UpdateCommandRequest(key=9, command=UpdateCommand.INSTALL, device_id=0),
        ),
        (
            "update_command",
            {"key": 9, "command": UpdateCommand.INSTALL, "device_id": 45},
            UpdateCommandRequest(key=9, command=UpdateCommand.INSTALL, device_id=45),
        ),
        # Cover command
        (
            "cover_command",
            {"key": 10, "position": 0.5},
            CoverCommandRequest(key=10, device_id=0),
        ),
        (
            "cover_command",
            {"key": 10, "position": 0.5, "device_id": 50},
            CoverCommandRequest(key=10, device_id=50),
        ),
        # Fan command
        (
            "fan_command",
            {"key": 11, "state": True},
            FanCommandRequest(key=11, device_id=0),
        ),
        (
            "fan_command",
            {"key": 11, "state": True, "device_id": 55},
            FanCommandRequest(key=11, device_id=55),
        ),
        # Light command
        (
            "light_command",
            {"key": 12, "state": True},
            LightCommandRequest(key=12, device_id=0),
        ),
        (
            "light_command",
            {"key": 12, "state": True, "device_id": 60},
            LightCommandRequest(key=12, device_id=60),
        ),
        # Climate command
        (
            "climate_command",
            {"key": 13, "target_temperature": 22.0},
            ClimateCommandRequest(key=13, device_id=0),
        ),
        (
            "climate_command",
            {"key": 13, "target_temperature": 22.0, "device_id": 65},
            ClimateCommandRequest(key=13, device_id=65),
        ),
        # Siren command
        (
            "siren_command",
            {"key": 14, "state": True},
            SirenCommandRequest(key=14, device_id=0),
        ),
        (
            "siren_command",
            {"key": 14, "state": True, "device_id": 70},
            SirenCommandRequest(key=14, device_id=70),
        ),
        # Lock command
        (
            "lock_command",
            {"key": 15, "command": LockCommand.LOCK},
            LockCommandRequest(key=15, command=LockCommand.LOCK, device_id=0),
        ),
        (
            "lock_command",
            {"key": 15, "command": LockCommand.LOCK, "device_id": 75},
            LockCommandRequest(key=15, command=LockCommand.LOCK, device_id=75),
        ),
        # Valve command
        (
            "valve_command",
            {"key": 16, "position": 0.5},
            ValveCommandRequest(key=16, device_id=0),
        ),
        (
            "valve_command",
            {"key": 16, "position": 0.5, "device_id": 80},
            ValveCommandRequest(key=16, device_id=80),
        ),
        # Media player command
        (
            "media_player_command",
            {"key": 17, "command": MediaPlayerCommand.PLAY},
            MediaPlayerCommandRequest(key=17, device_id=0),
        ),
        (
            "media_player_command",
            {"key": 17, "command": MediaPlayerCommand.PLAY, "device_id": 85},
            MediaPlayerCommandRequest(key=17, device_id=85),
        ),
        # Alarm control panel command
        (
            "alarm_control_panel_command",
            {"key": 18, "command": AlarmControlPanelCommand.DISARM},
            AlarmControlPanelCommandRequest(
                key=18, command=AlarmControlPanelCommand.DISARM, device_id=0
            ),
        ),
        (
            "alarm_control_panel_command",
            {"key": 18, "command": AlarmControlPanelCommand.DISARM, "device_id": 90},
            AlarmControlPanelCommandRequest(
                key=18, command=AlarmControlPanelCommand.DISARM, device_id=90
            ),
        ),
    ],
)
async def test_device_id_in_commands(
    auth_client: APIClient,
    method_name: str,
    method_args: dict[str, Any],
    expected_request: Any,
) -> None:
    """Test that device_id is properly passed through all command methods and defaults to 0."""
    send = patch_send(auth_client)
    # Set API version for commands that need it (like cover_command)
    patch_api_version(auth_client, APIVersion(1, 1))

    # Call the command method
    method = getattr(auth_client, method_name)
    method(**method_args)

    # Verify send_message was called once
    assert send.call_count == 1

    # Get the actual request that was sent
    actual_request = send.call_args[0][0]

    # Verify it's the correct request type
    assert type(actual_request) is type(expected_request)

    # Verify key and device_id match
    assert actual_request.key == expected_request.key
    assert actual_request.device_id == expected_request.device_id
