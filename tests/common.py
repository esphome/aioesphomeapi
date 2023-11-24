from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from functools import partial
from unittest.mock import AsyncMock, MagicMock, patch

from google.protobuf import message
from zeroconf import Zeroconf
from zeroconf.asyncio import AsyncZeroconf

from aioesphomeapi._frame_helper import APINoiseFrameHelper, APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.plain_text import _cached_varuint_to_bytes
from aioesphomeapi.api_pb2 import (
    ConnectResponse,
    HelloResponse,
    PingRequest,
    PingResponse,
)
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.core import MESSAGE_TYPE_TO_PROTO

UTC = timezone.utc
_MONOTONIC_RESOLUTION = time.get_clock_info("monotonic").resolution
# We use a partial here since it is implemented in native code
# and avoids the global lookup of UTC
utcnow: partial[datetime] = partial(datetime.now, UTC)
utcnow.__doc__ = "Get now in UTC time."

PROTO_TO_MESSAGE_TYPE = {v: k for k, v in MESSAGE_TYPE_TO_PROTO.items()}


def mock_data_received(
    protocol: APINoiseFrameHelper | APIPlaintextFrameHelper, data: bytes
) -> None:
    """Mock data received on the protocol."""
    try:
        protocol.data_received(data)
    except Exception as err:  # pylint: disable=broad-except
        loop = asyncio.get_running_loop()
        loop.call_soon(
            protocol.connection_lost,
            err,
        )


def get_mock_zeroconf() -> MagicMock:
    with patch("zeroconf.Zeroconf.start"):
        zc = Zeroconf()
        zc.close = MagicMock()
    return zc


def get_mock_async_zeroconf() -> AsyncZeroconf:
    aiozc = AsyncZeroconf(zc=get_mock_zeroconf())
    aiozc.async_close = AsyncMock()
    return aiozc


class Estr(str):
    """A subclassed string."""


def generate_plaintext_packet(msg: message.Message) -> bytes:
    type_ = PROTO_TO_MESSAGE_TYPE[msg.__class__]
    bytes_ = msg.SerializeToString()
    return (
        b"\0"
        + _cached_varuint_to_bytes(len(bytes_))
        + _cached_varuint_to_bytes(type_)
        + bytes_
    )


def as_utc(dattim: datetime) -> datetime:
    """Return a datetime as UTC time."""
    if dattim.tzinfo == UTC:
        return dattim
    return dattim.astimezone(UTC)


def async_fire_time_changed(
    datetime_: datetime | None = None, fire_all: bool = False
) -> None:
    """Fire a time changed event at an exact microsecond.

    Consider that it is not possible to actually achieve an exact
    microsecond in production as the event loop is not precise enough.
    If your code relies on this level of precision, consider a different
    approach, as this is only for testing.
    """
    loop = asyncio.get_running_loop()
    if datetime_ is None:
        utc_datetime = datetime.now(UTC)
    else:
        utc_datetime = as_utc(datetime_)

    timestamp = utc_datetime.timestamp()
    for task in list(loop._scheduled):
        if not isinstance(task, asyncio.TimerHandle):
            continue
        if task.cancelled():
            continue

        mock_seconds_into_future = timestamp - time.time()
        future_seconds = task.when() - (loop.time() + _MONOTONIC_RESOLUTION)

        if fire_all or mock_seconds_into_future >= future_seconds:
            task._run()
            task.cancel()


async def connect(conn: APIConnection, login: bool = True):
    """Wrapper for connection logic to do both parts."""
    await conn.start_connection()
    await conn.finish_connection(login=login)


def send_plaintext_hello(protocol: APIPlaintextFrameHelper) -> None:
    hello_response: message.Message = HelloResponse()
    hello_response.api_version_major = 1
    hello_response.api_version_minor = 9
    hello_response.name = "fake"
    protocol.data_received(generate_plaintext_packet(hello_response))


def send_plaintext_connect_response(
    protocol: APIPlaintextFrameHelper, invalid_password: bool
) -> None:
    connect_response: message.Message = ConnectResponse()
    connect_response.invalid_password = invalid_password
    protocol.data_received(generate_plaintext_packet(connect_response))


def send_ping_response(protocol: APIPlaintextFrameHelper) -> None:
    ping_response: message.Message = PingResponse()
    protocol.data_received(generate_plaintext_packet(ping_response))


def send_ping_request(protocol: APIPlaintextFrameHelper) -> None:
    ping_request: message.Message = PingRequest()
    protocol.data_received(generate_plaintext_packet(ping_request))


def get_mock_protocol(conn: APIConnection):
    protocol = APIPlaintextFrameHelper(
        connection=conn,
        client_info="mock",
        log_name="mock_device",
    )
    transport = MagicMock()
    protocol.connection_made(transport)
    return protocol
