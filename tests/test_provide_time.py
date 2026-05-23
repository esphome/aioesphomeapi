"""Tests for the provide_time flag on APIClient / ConnectionParams.

When provide_time=True (the default) the connection registers a handler
for GetTimeRequest and responds with the current epoch time, keeping the
device's clock in sync with the client.

When provide_time=False the handler is not registered, leaving the
device's clock untouched — useful for ESPHome's own log runner which
should not override timezone settings managed by Home Assistant.
"""

from __future__ import annotations

from dataclasses import replace
import time

from aioesphomeapi.api_pb2 import (  # type: ignore[attr-defined]
    GetTimeRequest,
    GetTimeResponse,
)

from .common import get_mock_connection_params
from .conftest import PatchableAPIClient, PatchableAPIConnection, mock_on_stop

# ---------------------------------------------------------------------------
# Tests: APIClient stores the flag correctly on _params
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Tests: _register_internal_message_handlers respects the flag
# ---------------------------------------------------------------------------


async def test_get_time_handler_registered_when_provide_time_true() -> None:
    """When provide_time=True the GetTimeRequest callback should be registered."""
    params = replace(get_mock_connection_params(), provide_time=True)
    conn = PatchableAPIConnection(params, mock_on_stop, True, None)

    registered_types: list[type] = []

    def capture(callback, msg_types):
        registered_types.extend(msg_types)

    conn._add_message_callback_without_remove = capture  # type: ignore[method-assign]
    conn._register_internal_message_handlers()

    assert GetTimeRequest in registered_types, (
        "GetTimeRequest handler should be registered when provide_time=True"
    )


async def test_get_time_handler_not_registered_when_provide_time_false() -> None:
    """When provide_time=False the GetTimeRequest callback must NOT be registered."""
    params = replace(get_mock_connection_params(), provide_time=False)
    conn = PatchableAPIConnection(params, mock_on_stop, True, None)

    registered_types: list[type] = []

    def capture(callback, msg_types):
        registered_types.extend(msg_types)

    conn._add_message_callback_without_remove = capture  # type: ignore[method-assign]
    conn._register_internal_message_handlers()

    assert GetTimeRequest not in registered_types, (
        "GetTimeRequest handler must not be registered when provide_time=False"
    )


# ---------------------------------------------------------------------------
# Tests: the time response handler sends a plausible epoch value
# ---------------------------------------------------------------------------


async def test_handle_get_time_request_sends_response() -> None:
    """_handle_get_time_request_internal should send a GetTimeResponse with current time."""
    params = replace(get_mock_connection_params(), provide_time=True)
    conn = PatchableAPIConnection(params, mock_on_stop, True, None)
    conn._handshake_complete = True

    sent_messages: list = []
    conn.send_messages = lambda msgs: sent_messages.extend(msgs)  # type: ignore[method-assign]

    before = int(time.time())
    conn._handle_get_time_request_internal(GetTimeRequest())
    after = int(time.time())

    assert len(sent_messages) == 1
    response = sent_messages[0]
    assert isinstance(response, GetTimeResponse)
    assert before <= response.epoch_seconds <= after + 1, (
        f"epoch_seconds {response.epoch_seconds} not in expected range [{before}, {after}]"
    )
