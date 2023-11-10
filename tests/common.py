from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from functools import partial
from unittest.mock import MagicMock

from zeroconf import Zeroconf

from aioesphomeapi._frame_helper.plain_text import _cached_varuint_to_bytes
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.core import MESSAGE_TYPE_TO_PROTO

UTC = timezone.utc
_MONOTONIC_RESOLUTION = time.get_clock_info("monotonic").resolution
# We use a partial here since it is implemented in native code
# and avoids the global lookup of UTC
utcnow: partial[datetime] = partial(datetime.now, UTC)
utcnow.__doc__ = "Get now in UTC time."

PROTO_TO_MESSAGE_TYPE = {v: k for k, v in MESSAGE_TYPE_TO_PROTO.items()}


def get_mock_zeroconf() -> MagicMock:
    return MagicMock(spec=Zeroconf)


class Estr(str):
    """A subclassed string."""


def generate_plaintext_packet(msg: bytes, type_: int) -> bytes:
    return (
        b"\0"
        + _cached_varuint_to_bytes(len(msg))
        + _cached_varuint_to_bytes(type_)
        + msg
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
