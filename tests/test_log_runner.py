from __future__ import annotations

import asyncio
from datetime import timedelta
from functools import partial
from unittest.mock import MagicMock, patch

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
from aioesphomeapi.reconnect_logic import EXPECTED_DISCONNECT_COOLDOWN

from .common import (
    Estr,
    async_fire_time_changed,
    generate_plaintext_packet,
    get_mock_async_zeroconf,
    mock_data_received,
    send_plaintext_connect_response,
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
        stop = await async_run(cli, on_log, aio_zeroconf_instance=async_zeroconf)
        await connected.wait()
        protocol = cli._connection._frame_helper
        send_plaintext_hello(protocol)
        send_plaintext_connect_response(protocol, False)
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
        stop = await async_run(cli, on_log, aio_zeroconf_instance=async_zeroconf)
        await connected.wait()
        protocol = cli._connection._frame_helper
        send_plaintext_hello(protocol)
        send_plaintext_connect_response(protocol, False)
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
            stop = await async_run(cli, on_log, aio_zeroconf_instance=async_zeroconf)
            await connected.wait()
            protocol = cli._connection._frame_helper
            send_plaintext_hello(protocol)
            send_plaintext_connect_response(protocol, False)

        await subscribed.wait()

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

    send_plaintext_connect_response(protocol, False)
    send_plaintext_hello(protocol)

    disconnect_response = DisconnectResponse()
    mock_data_received(protocol, generate_plaintext_packet(disconnect_response))

    await stop_task
