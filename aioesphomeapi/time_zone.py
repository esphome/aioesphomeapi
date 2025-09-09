"""Timezone detection utilities for aioesphomeapi."""

from __future__ import annotations

import asyncio
from functools import cache
from importlib import resources
import logging

import tzlocal

from .singleton import singleton

_LOGGER = logging.getLogger(__name__)


def _load_tzdata(iana_key: str) -> bytes | None:
    """Load timezone data from tzdata package."""
    try:
        package_loc, resource = iana_key.rsplit("/", 1)
    except ValueError:
        return None
    package = "tzdata.zoneinfo." + package_loc.replace("/", ".")

    try:
        return (resources.files(package) / resource).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError):
        return None


def _extract_tz_string(tzfile: bytes) -> str:
    """Extract POSIX TZ string from tzdata file."""
    try:
        return tzfile.split(b"\n")[-2].decode()
    except (IndexError, UnicodeDecodeError):
        _LOGGER.exception("Could not determine TZ string from tzfile")
        return ""


@cache
def _get_local_timezone() -> str:
    """Get the local timezone as a POSIX TZ string (synchronous, cached).

    Returns a POSIX TZ string like 'CST6CDT,M3.2.0,M11.1.0' for America/Chicago.
    Returns empty string if timezone cannot be determined.

    This function is cached since the timezone doesn't change during runtime.
    """
    try:
        iana_key = tzlocal.get_localzone_name()
        if iana_key is None:
            return ""

        tzfile = _load_tzdata(iana_key)
        if tzfile is None:
            # Not a IANA key, probably already a TZ string
            return str(iana_key)

        return _extract_tz_string(tzfile)
    except Exception:
        _LOGGER.exception("Failed to detect timezone")
        return ""


@singleton("local_timezone")
async def get_local_timezone() -> str:
    """Get the local timezone as a POSIX TZ string (async version).

    Returns a POSIX TZ string like 'CST6CDT,M3.2.0,M11.1.0' for America/Chicago.
    Returns empty string if timezone cannot be determined.

    This function runs in an executor to avoid blocking I/O and is cached
    using the singleton decorator.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_local_timezone)
