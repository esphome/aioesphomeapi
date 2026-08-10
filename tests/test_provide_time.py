"""Tests for the provide_time flag on APIClient / ConnectionParams.

When provide_time=True (the default) the connection registers a handler
for GetTimeRequest and responds to it, otherwise ignores the request.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from functools import partial
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

from aioesphomeapi.api_pb2 import (  # type: ignore[attr-defined]
    GetTimeRequest,
    GetTimeResponse,
)

from .common import (
    _create_mock_transport_protocol,
    connect,
    generate_plaintext_packet,
    get_mock_connection_params,
    mock_data_received,
    send_plaintext_hello,
)
from .conftest import PatchableAPIClient, PatchableAPIConnection, mock_on_stop

if TYPE_CHECKING:
    from collections.abc import Callable

    from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
    from aioesphomeapi.connection import APIConnection


async def test_api_client_provide_time_default() -> None:
    """provide_time should default to True."""
    cli = PatchableAPIClient(address="127.0.0.1", port=6052, password=None)
    assert cli._params.provide_time is True


async def test_api_client_provide_time_false() -> None:
    """provide_time=False should be stored on _params."""
    cli = PatchableAPIClient(
        address="127.0.0.1", port=6052, password=None, provide_time=False
    )
    assert cli._params.provide_time is False


async def _drain_loop_until(condition: Callable[[], bool], max_ticks: int = 25) -> None:
    """Spin the event loop until condition() holds, bounded by max_ticks."""
    for _ in range(max_ticks):
        if condition():
            return
        await asyncio.sleep(0)


async def _make_connected_conn(
    provide_time: bool,
    resolve_host,
    aiohappyeyeballs_start_connection,
    get_timezone_patch: Any = None,
) -> tuple[APIConnection, asyncio.Transport, APIPlaintextFrameHelper]:
    """Set up a plaintext-connected PatchableAPIConnection with provide_time set."""
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    params = replace(get_mock_connection_params(), provide_time=provide_time)
    conn = PatchableAPIConnection(params, mock_on_stop, True, None)

    if get_timezone_patch is None:
        get_timezone_patch = AsyncMock(return_value="UTC0")
    with (
        patch_create_connection(loop, transport, connected),
        patch("aioesphomeapi.connection.get_timezone", get_timezone_patch),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()
        send_plaintext_hello(conn._frame_helper)
        await connect_task
        return conn, transport, conn._frame_helper


def patch_create_connection(loop, transport, connected):
    return patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    )


async def test_get_time_response_sent_when_provide_time_true(
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> None:
    """A GetTimeRequest should produce a GetTimeResponse when provide_time=True."""
    conn, transport, protocol = await _make_connected_conn(
        provide_time=True,
        resolve_host=resolve_host,
        aiohappyeyeballs_start_connection=aiohappyeyeballs_start_connection,
    )

    try:
        transport.reset_mock()
        mock_data_received(protocol, generate_plaintext_packet(GetTimeRequest()))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert transport.writelines.call_count == 1, (
            "Expected exactly one frame to be written (the GetTimeResponse)"
        )
        raw = b"".join(transport.writelines.call_args[0][0])
        resp = GetTimeResponse()
        resp.ParseFromString(raw[3:])  # strip 3-byte plaintext frame header
        assert resp.epoch_seconds > 0, (
            f"Expected a valid epoch_seconds in GetTimeResponse, got {resp.epoch_seconds}"
        )
    finally:
        conn.force_disconnect()


async def test_get_time_response_not_sent_when_provide_time_false(
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> None:
    """A GetTimeRequest should produce no response when provide_time=False."""
    conn, transport, protocol = await _make_connected_conn(
        provide_time=False,
        resolve_host=resolve_host,
        aiohappyeyeballs_start_connection=aiohappyeyeballs_start_connection,
    )

    try:
        transport.reset_mock()
        mock_data_received(protocol, generate_plaintext_packet(GetTimeRequest()))
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        transport.write.assert_not_called()
        transport.writelines.assert_not_called()
    finally:
        conn.force_disconnect()


async def test_get_time_response_deferred_until_timezone_resolved(
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> None:
    """A GetTimeRequest received before the timezone resolves is answered after."""
    release = asyncio.Event()

    async def slow_get_timezone(_tz: str | None) -> str:
        await release.wait()
        return "UTC0"

    conn, transport, protocol = await _make_connected_conn(
        provide_time=True,
        resolve_host=resolve_host,
        aiohappyeyeballs_start_connection=aiohappyeyeballs_start_connection,
        get_timezone_patch=slow_get_timezone,
    )
    try:
        transport.reset_mock()
        mock_data_received(protocol, generate_plaintext_packet(GetTimeRequest()))
        await asyncio.sleep(0)
        transport.writelines.assert_not_called()

        release.set()
        await _drain_loop_until(lambda: transport.writelines.call_count == 1)

        assert transport.writelines.call_count == 1
        raw = b"".join(transport.writelines.call_args[0][0])
        resp = GetTimeResponse()
        resp.ParseFromString(raw[3:])  # strip 3-byte plaintext frame header
        assert resp.timezone == "UTC0"
    finally:
        conn.force_disconnect()


async def test_get_time_request_between_timezone_task_done_and_callback(
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> None:
    """A GetTimeRequest still gets a timezone when the task is done but its callback has not run."""
    release = asyncio.Event()

    async def slow_get_timezone(_tz: str | None) -> str:
        await release.wait()
        return "UTC0"

    conn, transport, protocol = await _make_connected_conn(
        provide_time=True,
        resolve_host=resolve_host,
        aiohappyeyeballs_start_connection=aiohappyeyeballs_start_connection,
        get_timezone_patch=slow_get_timezone,
    )
    try:
        transport.reset_mock()
        release.set()
        # One tick: the timezone task completes, but _set_cached_timezone is
        # still queued for the next callback batch.
        await asyncio.sleep(0)
        assert conn._timezone_task is not None
        assert conn._timezone_task.done()

        mock_data_received(protocol, generate_plaintext_packet(GetTimeRequest()))
        transport.writelines.assert_not_called()

        await _drain_loop_until(lambda: transport.writelines.call_count == 1)

        assert transport.writelines.call_count == 1
        raw = b"".join(transport.writelines.call_args[0][0])
        resp = GetTimeResponse()
        resp.ParseFromString(raw[3:])  # strip 3-byte plaintext frame header
        assert resp.timezone == "UTC0"
        assert conn._timezone_task is None
    finally:
        conn.force_disconnect()


async def test_get_time_response_empty_timezone_when_resolution_fails(
    resolve_host,
    aiohappyeyeballs_start_connection,
    caplog,
) -> None:
    """A failing timezone task logs a warning and the response carries no timezone."""
    release = asyncio.Event()

    async def failing_get_timezone(_tz: str | None) -> str:
        await release.wait()
        err = "tz boom"
        raise ValueError(err)

    conn, transport, protocol = await _make_connected_conn(
        provide_time=True,
        resolve_host=resolve_host,
        aiohappyeyeballs_start_connection=aiohappyeyeballs_start_connection,
        get_timezone_patch=failing_get_timezone,
    )
    try:
        transport.reset_mock()
        mock_data_received(protocol, generate_plaintext_packet(GetTimeRequest()))
        await asyncio.sleep(0)
        transport.writelines.assert_not_called()

        release.set()
        await _drain_loop_until(lambda: transport.writelines.call_count == 1)

        assert transport.writelines.call_count == 1
        raw = b"".join(transport.writelines.call_args[0][0])
        resp = GetTimeResponse()
        resp.ParseFromString(raw[3:])  # strip 3-byte plaintext frame header
        assert resp.timezone == ""
        assert resp.epoch_seconds > 0
        assert "Timezone resolution failed" in caplog.text
        assert conn._timezone_task is None
    finally:
        conn.force_disconnect()


async def test_timezone_not_resolved_when_provide_time_false(
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> None:
    """No timezone task is created when provide_time=False."""
    tz_mock = AsyncMock(return_value="UTC0")
    conn, _transport, _protocol = await _make_connected_conn(
        provide_time=False,
        resolve_host=resolve_host,
        aiohappyeyeballs_start_connection=aiohappyeyeballs_start_connection,
        get_timezone_patch=tz_mock,
    )
    try:
        assert tz_mock.call_count == 0
        assert conn._timezone_task is None
    finally:
        conn.force_disconnect()
