from __future__ import annotations

from asyncio import AbstractEventLoop, Task, get_running_loop
from collections.abc import Coroutine
import math
import sys
from typing import Any, TypeVar

_T = TypeVar("_T")


def fix_float_single_double_conversion(value: float) -> float:
    """Fix precision for single-precision floats and return what was probably
    meant as a float.

    In ESPHome we work with single-precision floats internally for performance.
    But python uses double-precision floats, and when protobuf reads the message
    it's auto-converted to a double (which is possible losslessly).

    Unfortunately the float representation of 0.1 converted to a double is not the
    double representation of 0.1, but 0.10000000149011612.

    This methods tries to round to the closest decimal value that a float of this
    magnitude can accurately represent.
    """
    if value == 0 or not math.isfinite(value):
        return value
    abs_val = abs(value)
    # assume ~7 decimals of precision for floats to be safe
    l10 = math.ceil(math.log10(abs_val))
    prec = 7 - l10
    return round(value, prec)


def host_is_name_part(address: str) -> bool:
    """Return True if a host is the name part."""
    return "." not in address and ":" not in address


def address_is_local(address: str) -> bool:
    """Return True if the address is a local address."""
    return address.removesuffix(".").endswith(".local")


def build_log_name(
    name: str | None, addresses: list[str], connected_address: str | None
) -> str:
    """Return a log name for a connection."""
    preferred_address = connected_address
    for address in addresses:
        if not name and address_is_local(address) or host_is_name_part(address):
            name = address.partition(".")[0]
        elif not preferred_address:
            preferred_address = address
    if not preferred_address:
        return name or addresses[0]
    if (
        name
        and name != preferred_address
        and not preferred_address.startswith(f"{name}.")
    ):
        return f"{name} @ {preferred_address}"
    return preferred_address


if sys.version_info >= (3, 12, 0):

    def create_eager_task(
        coro: Coroutine[Any, Any, _T],
        *,
        name: str | None = None,
        loop: AbstractEventLoop | None = None,
    ) -> Task[_T]:
        """Create a task from a coroutine and schedule it to run immediately."""
        return Task(
            coro,
            loop=loop or get_running_loop(),
            name=name,
            eager_start=True,  # type: ignore[call-arg]
        )

else:

    def create_eager_task(
        coro: Coroutine[Any, Any, _T],
        *,
        name: str | None = None,
        loop: AbstractEventLoop | None = None,
    ) -> Task[_T]:
        """Create a task from a coroutine."""
        return Task(coro, loop=loop or get_running_loop(), name=name)
