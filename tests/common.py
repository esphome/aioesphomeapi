from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from functools import partial
from unittest.mock import MagicMock
from zeroconf import Zeroconf
UTC = timezone.utc
_MONOTONIC_RESOLUTION = time.get_clock_info("monotonic").resolution
# We use a partial here since it is implemented in native code
# and avoids the global lookup of UTC
utcnow: partial[datetime] = partial(datetime.now, UTC)
utcnow.__doc__ = "Get now in UTC time."


def get_mock_zeroconf() -> MagicMock:
    return MagicMock(spec=Zeroconf)



class Estr(str):
    """A subclassed string."""


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
