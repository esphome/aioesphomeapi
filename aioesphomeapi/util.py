from __future__ import annotations

import math


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
    return "." not in address or ":" not in address


def build_log_name(name: str | None, address: str, resolved_address: str | None) -> str:
    """Return a log name for a connection."""
    if not name:
        if host_is_name_part(address):
            name = address
        if address.endswith(".local"):
            name = address[:-6]
    address = resolved_address or address
    if name and name != address:
        return f"{name} @ {address}"
    return address
