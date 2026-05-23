"""Tests for the provide_time flag on APIClient / ConnectionParams.

When provide_time=True (the default) the connection registers a handler
for GetTimeRequest and responds to it, otherwise ignores the request.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from functools import partial
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from aioesphomeapi.api_pb2 import GetTimeRequest  # type: ignore[attr-defined]

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


async def _make_connected_conn(
    provide_time: bool,
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> tuple[APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task]:
    """Set up a plaintext-connected PatchableAPIConnection with provide_time set."""
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    params = replace(get_mock_connection_params(), provide_time=provide_time)
    conn = PatchableAPIConnection(params, mock_on_stop, True, None)

    with patch_create_connection(loop, transport, connected):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()
        send_plaintext_hello(conn._frame_helper)
        await connect_task
        return conn, transport, conn._frame_helper


def patch_create_connection(loop, transport, connected):
    return __import__("unittest.mock", fromlist=["patch"]).patch.object(
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

        assert transport.write.called or transport.writelines.called, (
            "Expected transport.write to be called with a GetTimeResponse"
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
