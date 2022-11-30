import math
from typing import Optional


def varuint_to_bytes(value: int) -> bytes:
    if value <= 0x7F:
        return bytes([value])

    ret = bytes()
    while value:
        temp = value & 0x7F
        value >>= 7
        if value:
            ret += bytes([temp | 0x80])
        else:
            ret += bytes([temp])

    return ret


def bytes_to_varuint(value: bytes) -> Optional[int]:
    result = 0
    bitpos = 0
    for val in value:
        result |= (val & 0x7F) << bitpos
        if (val & 0x80) == 0:
            return result
        bitpos += 7
    return None


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
