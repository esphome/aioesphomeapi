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
from aioesphomeapi.log_runner import async_run
from aioesphomeapi.model import (
    ClimateInfo,
    ClimateMode,
    ClimateState,
    LogLevel,
    SensorInfo,
    SensorState,
    WaterHeaterInfo,
    WaterHeaterMode,
    WaterHeaterState,
)
from aioesphomeapi.reconnect_logic import EXPECTED_DISCONNECT_COOLDOWN, ReconnectLogic

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


async def test_async_run_with_subscribe_states() -> None:
    """Test async_run subscribes to states and emits synthetic log lines."""
    log_messages: list[SubscribeLogsResponse] = []
    state_callback = None

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(
        return_value=(
            MagicMock(),
            [
                SensorInfo(
                    key=1, name="CO2", unit_of_measurement="ppm", accuracy_decimals=0
                )
            ],
            [],
        )
    )

    def capture_subscribe_states(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe_states

    on_connect_callback = None

    class MockReconnectLogic(ReconnectLogic):
        def __init__(self, *, on_connect, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal on_connect_callback
            on_connect_callback = on_connect

        async def start(self) -> None:
            await on_connect_callback()

        async def stop(self) -> None:
            pass

    with patch("aioesphomeapi.log_runner.ReconnectLogic", MockReconnectLogic):
        stop = await async_run(
            cli,
            log_messages.append,
            subscribe_states=True,
        )

    assert state_callback is not None
    # subscribe_logs was called with the proxy callback (not our raw callback)
    cli.subscribe_logs.assert_called_once()
    assert cli.subscribe_logs.call_args[0][0] != log_messages.append

    # First state is skipped (initial dump)
    state_callback(SensorState(key=1, state=420.0))
    assert len(log_messages) == 0

    # Second state emits synthetic [S] log
    state_callback(SensorState(key=1, state=421.0))
    assert len(log_messages) == 1
    text = log_messages[0].message.decode()
    assert "[S][sensor]:" in text
    assert "'CO2' >> 421 ppm" in text
    assert "\033[0;96m" in text

    await stop()


async def test_async_run_with_colliding_entity_keys_across_types() -> None:
    """Two entities of different types sharing a device_id+key must each
    resolve to their own info in the log runner.

    Reproducer: a climate and a water_heater on the same device with names
    that hash to the same entity key (e.g. both named "Water Heater" in an
    external component). The on-wire key is platform-agnostic so both
    entities ship with the same key; the log runner must still dispatch each
    state to the info of the matching type rather than last-write-wins.
    """
    log_messages: list[SubscribeLogsResponse] = []
    state_callback = None

    climate_info = ClimateInfo(
        key=1, name="Water Heater", supports_two_point_target_temperature=False
    )
    water_heater_info = WaterHeaterInfo(key=1, name="Water Heater")

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(
        return_value=(MagicMock(), [climate_info, water_heater_info], [])
    )

    def capture_subscribe_states(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe_states

    on_connect_callback = None

    class MockReconnectLogic(ReconnectLogic):
        def __init__(self, *, on_connect, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal on_connect_callback
            on_connect_callback = on_connect

        async def start(self) -> None:
            await on_connect_callback()

        async def stop(self) -> None:
            pass

    with patch("aioesphomeapi.log_runner.ReconnectLogic", MockReconnectLogic):
        stop = await async_run(cli, log_messages.append, subscribe_states=True)

    assert state_callback is not None

    # Each entity type gets its own initial-dump skip; the second entity's
    # first real state must not be swallowed just because (device_id, key)
    # was already seen for the other type.
    state_callback(
        ClimateState(
            key=1,
            mode=ClimateMode.HEAT,
            current_temperature=20.0,
            target_temperature=22.0,
        )
    )
    state_callback(WaterHeaterState(key=1, mode=WaterHeaterMode.HEAT_PUMP))
    assert len(log_messages) == 0

    # WaterHeaterState with key=1 must resolve to WaterHeaterInfo (not the
    # ClimateInfo that was listed first for the same key), proving ordering
    # does not matter.
    state_callback(WaterHeaterState(key=1, mode=WaterHeaterMode.HEAT_PUMP))
    assert len(log_messages) == 1
    assert "[S][water_heater]: 'Water Heater' >>" in log_messages[0].message.decode()

    # ClimateState must not crash on WaterHeaterInfo-specific fields and
    # must render as a climate line (proves the correct info was selected).
    state_callback(
        ClimateState(
            key=1,
            mode=ClimateMode.HEAT,
            current_temperature=20.5,
            target_temperature=22.0,
        )
    )
    assert len(log_messages) == 2
    text = log_messages[1].message.decode()
    assert "[S][climate]: 'Water Heater' >>" in text
    assert "Mode: HEAT" in text
    assert "Current Temperature: 20.50" in text

    await stop()


async def test_async_run_warns_on_unmapped_state_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unmapped state type (future protobuf addition without a
    STATE_TYPE_TO_INFO_TYPE entry) must warn rather than silently pass
    info=None to the formatter.
    """
    log_messages: list[SubscribeLogsResponse] = []
    state_callback = None

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(return_value=(MagicMock(), [], []))

    def capture_subscribe_states(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe_states

    on_connect_callback = None

    class MockReconnectLogic(ReconnectLogic):
        def __init__(self, *, on_connect, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal on_connect_callback
            on_connect_callback = on_connect

        async def start(self) -> None:
            await on_connect_callback()

        async def stop(self) -> None:
            pass

    class UnmappedState(SensorState):
        """Stand-in for a future state type with no mapping entry."""

    with patch("aioesphomeapi.log_runner.ReconnectLogic", MockReconnectLogic):
        stop = await async_run(cli, log_messages.append, subscribe_states=True)

    assert state_callback is not None

    # Skip initial dump, then deliver an unmapped state type.
    state_callback(UnmappedState(key=1, state=1.0))
    caplog.clear()
    state_callback(UnmappedState(key=1, state=2.0))

    assert "No EntityInfo type mapping for state UnmappedState" in caplog.text

    await stop()


async def test_async_run_with_subscribe_states_suppresses_on_verbose() -> None:
    """Test that verbose firmware logs suppress synthetic state lines."""
    log_messages: list[SubscribeLogsResponse] = []
    state_callback = None
    log_proxy_callback = None

    cli = MagicMock(spec=APIClient)
    cli.device_info_and_list_entities = AsyncMock(
        return_value=(MagicMock(), [MagicMock(key=1, name="Temp")], [])
    )

    def capture_subscribe_states(cb: object) -> None:
        nonlocal state_callback
        state_callback = cb

    cli.subscribe_states = capture_subscribe_states

    def capture_subscribe_logs(cb: object, **kwargs: object) -> None:
        nonlocal log_proxy_callback
        log_proxy_callback = cb

    cli.subscribe_logs = capture_subscribe_logs

    on_connect_callback = None

    class MockReconnectLogic(ReconnectLogic):
        def __init__(self, *, on_connect, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal on_connect_callback
            on_connect_callback = on_connect

        async def start(self) -> None:
            await on_connect_callback()

        async def stop(self) -> None:
            pass

    with patch("aioesphomeapi.log_runner.ReconnectLogic", MockReconnectLogic):
        stop = await async_run(cli, log_messages.append, subscribe_states=True)

    assert state_callback is not None
    assert log_proxy_callback is not None

    # Skip initial state
    state_callback(SensorState(key=1, state=20.0))

    # Simulate verbose log arriving through the proxy
    verbose_msg = SubscribeLogsResponse()
    verbose_msg.level = LogLevel.LOG_LEVEL_VERBOSE
    verbose_msg.message = b"verbose log"
    log_proxy_callback(verbose_msg)
    # The verbose log itself was forwarded
    assert len(log_messages) == 1
    assert log_messages[0].message == b"verbose log"

    # State change should now be suppressed
    state_callback(SensorState(key=1, state=21.0))
    assert len(log_messages) == 1  # No new message

    await stop()


async def test_async_run_without_subscribe_states() -> None:
    """Test async_run with subscribe_states=False skips state subscription."""
    log_messages: list[SubscribeLogsResponse] = []

    cli = MagicMock(spec=APIClient)

    on_connect_callback = None

    class MockReconnectLogic(ReconnectLogic):
        def __init__(self, *, on_connect, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal on_connect_callback
            on_connect_callback = on_connect

        async def start(self) -> None:
            await on_connect_callback()

        async def stop(self) -> None:
            pass

    with patch("aioesphomeapi.log_runner.ReconnectLogic", MockReconnectLogic):
        stop = await async_run(cli, log_messages.append, subscribe_states=False)

    # subscribe_logs called with raw callback
    cli.subscribe_logs.assert_called_once()
    assert cli.subscribe_logs.call_args[0][0] == log_messages.append
    # No state subscription
    cli.subscribe_states.assert_not_called()
    cli.device_info_and_list_entities.assert_not_called()

    await stop()


async def test_async_run_disconnects_on_api_connection_error() -> None:
    """Test that APIConnectionError during on_connect triggers disconnect."""
    cli = MagicMock(spec=APIClient)
    cli.subscribe_logs.side_effect = APIConnectionError("fail")
    cli.disconnect = AsyncMock()

    on_connect_callback = None

    class MockReconnectLogic(ReconnectLogic):
        def __init__(self, *, on_connect, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal on_connect_callback
            on_connect_callback = on_connect

        async def start(self) -> None:
            await on_connect_callback()

        async def stop(self) -> None:
            pass

    with patch("aioesphomeapi.log_runner.ReconnectLogic", MockReconnectLogic):
        stop = await async_run(cli, lambda _: None, subscribe_states=False)

    cli.disconnect.assert_called_once()
    await stop()


async def test_async_run_on_disconnect_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that on_disconnect logs a warning."""
    cli = MagicMock(spec=APIClient)
    cli.disconnect = AsyncMock()

    on_disconnect_callback = None

    class MockReconnectLogic(ReconnectLogic):
        def __init__(self, *, on_connect, on_disconnect, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal on_disconnect_callback
            on_disconnect_callback = on_disconnect

        async def start(self) -> None:
            pass

        async def stop(self) -> None:
            pass

    with patch("aioesphomeapi.log_runner.ReconnectLogic", MockReconnectLogic):
        stop = await async_run(cli, lambda _: None, subscribe_states=False)

    assert on_disconnect_callback is not None
    await on_disconnect_callback(expected_disconnect=True)
    assert "Disconnected from API" in caplog.text

    await stop()
