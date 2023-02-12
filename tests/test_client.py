from sys import version

import pytest
from mock import AsyncMock, MagicMock, call, patch

from aioesphomeapi.api_pb2 import (
    BinarySensorStateResponse,
    CameraImageRequest,
    CameraImageResponse,
    ClimateCommandRequest,
    CoverCommandRequest,
    ExecuteServiceArgument,
    ExecuteServiceRequest,
    FanCommandRequest,
    LightCommandRequest,
    ListEntitiesBinarySensorResponse,
    ListEntitiesDoneResponse,
    ListEntitiesServicesResponse,
    LockCommandRequest,
    MediaPlayerCommandRequest,
    NumberCommandRequest,
    SelectCommandRequest,
    SwitchCommandRequest,
)
from aioesphomeapi.client import APIClient
from aioesphomeapi.model import (
    APIVersion,
    BinarySensorInfo,
    BinarySensorState,
    CameraState,
    ClimateFanMode,
    ClimateMode,
    ClimatePreset,
    ClimateSwingMode,
    FanDirection,
    FanSpeed,
    LegacyCoverCommand,
    LockCommand,
    MediaPlayerCommand,
    UserService,
    UserServiceArg,
    UserServiceArgType,
)


@pytest.fixture
def auth_client():
    client = APIClient(
        address="fake.address",
        port=6052,
        password=None,
    )
    with patch.object(client, "_connection") as conn:
        conn.is_connected = True
        conn.is_authenticated = True
        yield client


def patch_response_complex(client: APIClient, messages):
    async def patched(req, app, stop, msg_types, timeout=5.0):
        resp = []
        for msg in messages:
            if app(msg):
                resp.append(msg)
            if stop(msg):
                break
        else:
            raise ValueError("Response never stopped")
        return resp

    client._connection.send_message_await_response_complex = patched


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
    send = client._connection.send_message = AsyncMock()
    return send


def patch_api_version(client: APIClient, version: APIVersion):
    client._connection.api_version = version


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
async def test_list_entities(auth_client, input, output):
    patch_response_complex(auth_client, input)
    resp = await auth_client.list_entities_services()
    assert resp == output


@pytest.mark.asyncio
async def test_subscribe_states(auth_client):
    send = patch_response_callback(auth_client)
    on_state = MagicMock()
    await auth_client.subscribe_states(on_state)
    on_state.assert_not_called()

    await send(BinarySensorStateResponse())
    on_state.assert_called_once_with(BinarySensorState())


@pytest.mark.asyncio
async def test_subscribe_states_camera(auth_client):
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
async def test_cover_command_legacy(auth_client, cmd, req):
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
async def test_cover_command(auth_client, cmd, req):
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
async def test_fan_command(auth_client, cmd, req):
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
            dict(key=1, transition_length=0.1),
            dict(key=1, has_transition_length=True, transition_length=100),
        ),
        (
            dict(key=1, flash_length=0.1),
            dict(key=1, has_flash_length=True, flash_length=100),
        ),
        (dict(key=1, effect="special"), dict(key=1, has_effect=True, effect="special")),
    ],
)
async def test_light_command(auth_client, cmd, req):
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
async def test_switch_command(auth_client, cmd, req):
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
async def test_climate_command_legacy(auth_client, cmd, req):
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
async def test_climate_command(auth_client, cmd, req):
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
async def test_number_command(auth_client, cmd, req):
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
    ],
)
async def test_lock_command(auth_client, cmd, req):
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
async def test_select_command(auth_client, cmd, req):
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
async def test_media_player_command(auth_client, cmd, req):
    send = patch_send(auth_client)

    await auth_client.media_player_command(**cmd)
    send.assert_called_once_with(MediaPlayerCommandRequest(**req))


@pytest.mark.asyncio
async def test_execute_service(auth_client):
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
async def test_request_single_image(auth_client):
    send = patch_send(auth_client)

    await auth_client.request_single_image()
    send.assert_called_once_with(CameraImageRequest(single=True, stream=False))


@pytest.mark.asyncio
async def test_request_image_stream(auth_client):
    send = patch_send(auth_client)

    await auth_client.request_image_stream()
    send.assert_called_once_with(CameraImageRequest(single=False, stream=True))
