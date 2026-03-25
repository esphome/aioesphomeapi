from __future__ import annotations

import asyncio
from datetime import timedelta
from functools import partial
from unittest.mock import AsyncMock, MagicMock, patch

from google.protobuf import message
import pytest

from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.api_pb2 import (
    DisconnectRequest,
    DisconnectResponse,
    SubscribeLogsResponse,  # type: ignore
)
from aioesphomeapi.client import APIClient
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.core import APIConnectionError
from aioesphomeapi.log_runner import _StateLogProxy, _subscribe_entity_states, async_run
from aioesphomeapi.model import LightInfo, LightState, LogLevel, SensorInfo, SensorState
from aioesphomeapi.reconnect_logic import EXPECTED_DISCONNECT_COOLDOWN

from .common import (
    Estr,
    async_fire_time_changed,
    generate_plaintext_packet,
    get_mock_async_zeroconf,
    mock_data_received,
    send_plaintext_auth_response,
    send_plaintext_hello,
    utcnow,
)


async def test_log_runner(
    conn: APIConnection,
    aiohappyeyeballs_start_connection,
):
    """Test the log runner logic."""
    loop = asyncio.get_running_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()

    cli = PatchableAPIClient(
        address=Estr("127.0.0.1"),
        port=6052,
        password=None,
        noise_psk=None,
        expected_name=Estr("fake"),
        zeroconf_instance=async_zeroconf.zeroconf,
    )
    messages = []

    def on_log(msg: SubscribeLogsResponse) -> None:
        messages.append(msg)

    def _create_mock_transport_protocol(create_func, **kwargs):
        nonlocal protocol
        protocol = create_func()
        protocol.connection_made(transport)
        connected.set()
        return transport, protocol

    subscribed = asyncio.Event()
    original_subscribe_logs = cli.subscribe_logs

    def _wait_subscribe_cli(*args, **kwargs):
        original_subscribe_logs(*args, **kwargs)
        subscribed.set()

    with (
        patch.object(
            loop, "create_connection", side_effect=_create_mock_transport_protocol
        ),
        patch.object(cli, "subscribe_logs", _wait_subscribe_cli),
    ):
        stop = await async_run(
            cli,
            on_log,
            aio_zeroconf_instance=async_zeroconf,
            subscribe_states=False,
        )
        await connected.wait()
        protocol = cli._connection._frame_helper
        send_plaintext_hello(protocol)
        send_plaintext_auth_response(protocol, False)
        await subscribed.wait()

    response: message.Message = SubscribeLogsResponse()
    response.message = b"Hello world"
    mock_data_received(protocol, generate_plaintext_packet(response))
    assert len(messages) == 1
    assert messages[0].message == b"Hello world"
    stop_task = asyncio.create_task(stop())
    await asyncio.sleep(0)
    disconnect_response = DisconnectResponse()
    mock_data_received(protocol, generate_plaintext_packet(disconnect_response))
    await stop_task


async def test_log_runner_reconnects_on_disconnect(
    conn: APIConnection,
    caplog: pytest.LogCaptureFixture,
    aiohappyeyeballs_start_connection,
) -> None:
    """Test the log runner reconnects on disconnect."""
    loop = asyncio.get_running_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()

    cli = PatchableAPIClient(
        address=Estr("127.0.0.1"),
        port=6052,
        password=None,
        noise_psk=None,
        expected_name=Estr("fake"),
        zeroconf_instance=async_zeroconf.zeroconf,
    )
    messages = []

    def on_log(msg: SubscribeLogsResponse) -> None:
        messages.append(msg)

    def _create_mock_transport_protocol(create_func, **kwargs):
        nonlocal protocol
        protocol = create_func()
        protocol.connection_made(transport)
        connected.set()
        return transport, protocol

    subscribed = asyncio.Event()
    original_subscribe_logs = cli.subscribe_logs

    def _wait_subscribe_cli(*args, **kwargs):
        original_subscribe_logs(*args, **kwargs)
        subscribed.set()

    with (
        patch.object(
            loop, "create_connection", side_effect=_create_mock_transport_protocol
        ),
        patch.object(cli, "subscribe_logs", _wait_subscribe_cli),
    ):
        stop = await async_run(
            cli,
            on_log,
            aio_zeroconf_instance=async_zeroconf,
            subscribe_states=False,
        )
        await connected.wait()
        protocol = cli._connection._frame_helper
        send_plaintext_hello(protocol)
        send_plaintext_auth_response(protocol, False)
        await subscribed.wait()

    response: message.Message = SubscribeLogsResponse()
    response.message = b"Hello world"
    mock_data_received(protocol, generate_plaintext_packet(response))
    assert len(messages) == 1
    assert messages[0].message == b"Hello world"

    with patch.object(cli, "start_resolve_host") as mock_start_resolve_host:
        response: message.Message = DisconnectRequest()
        mock_data_received(protocol, generate_plaintext_packet(response))

        await asyncio.sleep(0)
        assert cli._connection is None
        async_fire_time_changed(
            utcnow() + timedelta(seconds=EXPECTED_DISCONNECT_COOLDOWN)
        )
        await asyncio.sleep(0)

    assert "Disconnected from API" in caplog.text
    assert mock_start_resolve_host.called

    await stop()


async def test_log_runner_reconnects_on_subscribe_failure(
    conn: APIConnection,
    caplog: pytest.LogCaptureFixture,
    aiohappyeyeballs_start_connection,
) -> None:
    """Test the log runner reconnects on subscribe failure."""
    loop = asyncio.get_running_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()

    cli = PatchableAPIClient(
        address=Estr("127.0.0.1"),
        port=6052,
        password=None,
        noise_psk=None,
        expected_name=Estr("fake"),
        zeroconf_instance=async_zeroconf.zeroconf,
    )
    messages = []

    def on_log(msg: SubscribeLogsResponse) -> None:
        messages.append(msg)

    def _create_mock_transport_protocol(create_func, **kwargs):
        nonlocal protocol
        protocol = create_func()
        protocol.connection_made(transport)
        connected.set()
        return transport, protocol

    subscribed = asyncio.Event()

    def _wait_and_fail_subscribe_cli(*args, **kwargs):
        subscribed.set()
        raise APIConnectionError("subscribed force to fail")

    with (
        patch.object(cli, "disconnect", partial(cli.disconnect, force=True)),
        patch.object(cli, "subscribe_logs", _wait_and_fail_subscribe_cli),
    ):
        with patch.object(
            loop, "create_connection", side_effect=_create_mock_transport_protocol
        ):
            stop = await async_run(
                cli,
                on_log,
                aio_zeroconf_instance=async_zeroconf,
                subscribe_states=False,
            )
            await connected.wait()
            protocol = cli._connection._frame_helper
            send_plaintext_hello(protocol)
            send_plaintext_auth_response(protocol, False)

        await asyncio.wait_for(subscribed.wait(), timeout=1)

    assert cli._connection is None

    with (
        patch.object(
            loop, "create_connection", side_effect=_create_mock_transport_protocol
        ),
        patch.object(cli, "subscribe_logs"),
    ):
        connected.clear()
        await asyncio.sleep(0)
        async_fire_time_changed(
            utcnow() + timedelta(seconds=EXPECTED_DISCONNECT_COOLDOWN)
        )
        await asyncio.sleep(0)

    stop_task = asyncio.create_task(stop())
    await asyncio.sleep(0)

    send_plaintext_hello(protocol)
    send_plaintext_auth_response(protocol, False)

    await asyncio.sleep(0)
    await asyncio.sleep(0)
    disconnect_response = DisconnectResponse()
    mock_data_received(protocol, generate_plaintext_packet(disconnect_response))

    await asyncio.wait_for(stop_task, timeout=1)


def test_state_log_proxy_forwards_log_messages() -> None:
    messages: list[SubscribeLogsResponse] = []
    proxy = _StateLogProxy(messages.append)
    msg = SubscribeLogsResponse()
    msg.level = LogLevel.LOG_LEVEL_DEBUG
    msg.message = b"test"
    proxy.on_log(msg)
    assert len(messages) == 1
    assert messages[0].message == b"test"


def test_state_log_proxy_not_seen_verbose_initially() -> None:
    proxy = _StateLogProxy(lambda _: None)
    assert proxy.seen_verbose is False


def test_state_log_proxy_detects_verbose_level() -> None:
    proxy = _StateLogProxy(lambda _: None)
    msg = SubscribeLogsResponse()
    msg.level = LogLevel.LOG_LEVEL_VERBOSE
    proxy.on_log(msg)
    assert proxy.seen_verbose is True


def test_state_log_proxy_detects_very_verbose_level() -> None:
    proxy = _StateLogProxy(lambda _: None)
    msg = SubscribeLogsResponse()
    msg.level = LogLevel.LOG_LEVEL_VERY_VERBOSE
    proxy.on_log(msg)
    assert proxy.seen_verbose is True


def test_state_log_proxy_does_not_trigger_on_debug() -> None:
    proxy = _StateLogProxy(lambda _: None)
    msg = SubscribeLogsResponse()
    msg.level = LogLevel.LOG_LEVEL_DEBUG
    proxy.on_log(msg)
    assert proxy.seen_verbose is False


def test_state_log_proxy_does_not_trigger_on_info() -> None:
    proxy = _StateLogProxy(lambda _: None)
    msg = SubscribeLogsResponse()
    msg.level = LogLevel.LOG_LEVEL_INFO
    proxy.on_log(msg)
    assert proxy.seen_verbose is False


async def test_subscribe_entity_states_skips_initial_state() -> None:
    """First state per key should be skipped."""
    messages: list[SubscribeLogsResponse] = []
    proxy = _StateLogProxy(lambda _: None)

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(
        return_value=(
            MagicMock(),
            [MagicMock(key=1, name="Sensor1")],
            [],
        )
    )
    state_callback = None

    def capture_subscribe(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe

    await _subscribe_entity_states(cli, messages.append, proxy)
    assert state_callback is not None

    # First state should be skipped
    state_callback(SensorState(key=1, state=42.0))
    assert len(messages) == 0

    # Second state should emit
    state_callback(SensorState(key=1, state=43.0))
    assert len(messages) == 1


async def test_subscribe_entity_states_emits_synthetic_log_with_ansi_color() -> None:
    """Synthetic log should have ANSI color and [S] prefix."""
    messages: list[SubscribeLogsResponse] = []
    proxy = _StateLogProxy(lambda _: None)

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(
        return_value=(
            MagicMock(),
            [
                SensorInfo(
                    key=1,
                    name="CO2",
                    unit_of_measurement="ppm",
                    accuracy_decimals=0,
                )
            ],
            [],
        )
    )
    state_callback = None

    def capture_subscribe(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe

    await _subscribe_entity_states(cli, messages.append, proxy)

    # Skip initial
    state_callback(SensorState(key=1, state=420.0))
    # This one emits
    state_callback(SensorState(key=1, state=421.0))
    assert len(messages) == 1
    text = messages[0].message.decode()
    assert "[S][sensor]:" in text
    assert "'CO2' >> 421 ppm" in text
    assert "\033[0;96m" in text
    assert "\033[0m" in text
    assert messages[0].level == LogLevel.LOG_LEVEL_DEBUG


async def test_subscribe_entity_states_multiline_ansi_color() -> None:
    """Each line in multi-line state should get ANSI color."""
    messages: list[SubscribeLogsResponse] = []
    proxy = _StateLogProxy(lambda _: None)

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(
        return_value=(
            MagicMock(),
            [LightInfo(key=1, name="Light")],
            [],
        )
    )
    state_callback = None

    def capture_subscribe(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe

    await _subscribe_entity_states(cli, messages.append, proxy)

    # Skip initial
    state_callback(LightState(key=1, state=True, brightness=0.5))
    # This one emits
    state_callback(LightState(key=1, state=True, brightness=0.8))
    assert len(messages) == 1
    text = messages[0].message.decode()
    lines = text.split("\n")
    # Each line should start with color and end with reset
    for line in lines:
        assert line.startswith("\033[0;96m"), f"Missing color start: {line!r}"
        assert line.endswith("\033[0m"), f"Missing color reset: {line!r}"


async def test_subscribe_entity_states_suppresses_after_verbose_detected() -> None:
    """After verbose log seen, no more synthetic states."""
    messages: list[SubscribeLogsResponse] = []
    proxy = _StateLogProxy(lambda _: None)

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(
        return_value=(
            MagicMock(),
            [MagicMock(key=1, name="Temp")],
            [],
        )
    )
    state_callback = None

    def capture_subscribe(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe

    await _subscribe_entity_states(cli, messages.append, proxy)

    # Skip initial
    state_callback(SensorState(key=1, state=20.0))

    # Simulate verbose log detected
    verbose_msg = SubscribeLogsResponse()
    verbose_msg.level = LogLevel.LOG_LEVEL_VERBOSE
    proxy.on_log(verbose_msg)

    # This should be suppressed
    state_callback(SensorState(key=1, state=21.0))
    assert len(messages) == 0


async def test_subscribe_entity_states_different_device_ids_tracked_separately() -> (
    None
):
    """Different device_ids with same key are separate entities."""
    messages: list[SubscribeLogsResponse] = []
    proxy = _StateLogProxy(lambda _: None)

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(
        return_value=(
            MagicMock(),
            [MagicMock(key=1, name="Sensor")],
            [],
        )
    )
    state_callback = None

    def capture_subscribe(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe

    await _subscribe_entity_states(cli, messages.append, proxy)

    # Initial for device_id=0
    state_callback(SensorState(key=1, device_id=0, state=1.0))
    assert len(messages) == 0
    # Initial for device_id=1
    state_callback(SensorState(key=1, device_id=1, state=2.0))
    assert len(messages) == 0
    # Second for device_id=0 should emit
    state_callback(SensorState(key=1, device_id=0, state=3.0))
    assert len(messages) == 1
