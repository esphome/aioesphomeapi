"""POSIX TZ string parser for aioesphomeapi.

Parses POSIX TZ strings (e.g., "EST5EDT,M3.2.0,M11.1.0") into a structured
ParsedTimezone representation. This is a Python port of ESPHome's C++ parser
in posix_tz.cpp, producing identical field values for all inputs.

The parsed struct can be used to:
- Pre-compute timezone data at codegen time (ESPHome Step 2)
- Send pre-parsed timezone over protobuf (ESPHome Step 3)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class DSTRuleType(IntEnum):
    """Type of DST transition rule."""

    NONE = 0
    MONTH_WEEK_DAY = 1  # M format: Mm.w.d
    JULIAN_NO_LEAP = 2  # J format: Jn (day 1-365, Feb 29 not counted)
    DAY_OF_YEAR = 3  # Plain number: n (day 0-365, Feb 29 counted)


@dataclass
class DSTRule:
    """Rule for DST transition."""

    time_seconds: int = (
        0  # Seconds after midnight (default 7200 = 2:00 AM set by parser)
    )
    day: int = 0  # Day of year (for JULIAN_NO_LEAP and DAY_OF_YEAR)
    type: DSTRuleType = DSTRuleType.NONE
    month: int = 0  # Month 1-12 (for MONTH_WEEK_DAY)
    week: int = 0  # Week 1-5, 5 = last (for MONTH_WEEK_DAY)
    day_of_week: int = 0  # Day 0-6, 0 = Sunday (for MONTH_WEEK_DAY)


@dataclass
class ParsedTimezone:
    """Parsed POSIX timezone information."""

    std_offset_seconds: int = 0  # Standard time offset (positive = west of UTC)
    dst_offset_seconds: int = 0  # DST offset from UTC
    dst_start: DSTRule = field(default_factory=DSTRule)
    dst_end: DSTRule = field(default_factory=DSTRule)

    @property
    def has_dst(self) -> bool:
        """Check if this timezone has DST rules."""
        return self.dst_start.type != DSTRuleType.NONE


def _skip_tz_name(s: str, pos: int) -> int:
    """Skip a timezone name (letters or <...> quoted format).

    Returns new position after the name.
    Raises ValueError if name is invalid.
    """
    if pos >= len(s):
        raise ValueError("Unexpected end of string, expected timezone name")

    if s[pos] == "<":
        # Angle-bracket quoted name: <+07>, <-03>, <AEST>
        pos += 1  # skip '<'
        while pos < len(s) and s[pos] != ">":
            pos += 1
        if pos >= len(s):
            raise ValueError("Unterminated angle-bracket timezone name")
        pos += 1  # skip '>'
        return pos

    # Standard name: 3+ letters
    start = pos
    while pos < len(s) and s[pos].isalpha():
        pos += 1
    if pos - start < 3:
        raise ValueError(f"Timezone name must be at least 3 letters, got {pos - start}")
    return pos


def _parse_offset(s: str, pos: int) -> tuple[int, int]:
    """Parse an offset in format [-]hh[:mm[:ss]].

    Returns (offset_in_seconds, new_position).
    """
    sign = 1
    if pos < len(s) and s[pos] == "-":
        sign = -1
        pos += 1
    elif pos < len(s) and s[pos] == "+":
        pos += 1

    hours, pos = _parse_uint(s, pos)
    minutes = 0
    seconds = 0

    if pos < len(s) and s[pos] == ":":
        pos += 1
        minutes, pos = _parse_uint(s, pos)
        if pos < len(s) and s[pos] == ":":
            pos += 1
            seconds, pos = _parse_uint(s, pos)

    return sign * (hours * 3600 + minutes * 60 + seconds), pos


def _parse_uint(s: str, pos: int) -> tuple[int, int]:
    """Parse an unsigned integer from string at position.

    Returns (value, new_position).
    """
    value = 0
    while pos < len(s) and s[pos].isdigit():
        value = value * 10 + int(s[pos])
        pos += 1
    return value, pos


def _parse_dst_rule(s: str, pos: int) -> tuple[DSTRule, int]:
    """Parse a DST rule in format Mm.w.d[/time], Jn[/time], or n[/time].

    Returns (DSTRule, new_position).
    Raises ValueError on invalid input.
    """
    rule = DSTRule()

    if pos >= len(s):
        raise ValueError("Unexpected end of string, expected DST rule")

    if s[pos] in ("M", "m"):
        # M format: Mm.w.d
        rule.type = DSTRuleType.MONTH_WEEK_DAY
        pos += 1

        rule.month, pos = _parse_uint(s, pos)
        if rule.month < 1 or rule.month > 12:
            raise ValueError(f"Month must be 1-12, got {rule.month}")

        if pos >= len(s) or s[pos] != ".":
            raise ValueError("Expected '.' after month in M-format rule")
        pos += 1

        rule.week, pos = _parse_uint(s, pos)
        if rule.week < 1 or rule.week > 5:
            raise ValueError(f"Week must be 1-5, got {rule.week}")

        if pos >= len(s) or s[pos] != ".":
            raise ValueError("Expected '.' after week in M-format rule")
        pos += 1

        rule.day_of_week, pos = _parse_uint(s, pos)
        if rule.day_of_week > 6:
            raise ValueError(f"Day of week must be 0-6, got {rule.day_of_week}")

    elif s[pos] in ("J", "j"):
        # J format: Jn (Julian day 1-365, not counting Feb 29)
        rule.type = DSTRuleType.JULIAN_NO_LEAP
        pos += 1

        rule.day, pos = _parse_uint(s, pos)
        if rule.day < 1 or rule.day > 365:
            raise ValueError(f"Julian day must be 1-365, got {rule.day}")

    elif s[pos].isdigit():
        # Plain number format: n (day 0-365, counting Feb 29)
        rule.type = DSTRuleType.DAY_OF_YEAR

        rule.day, pos = _parse_uint(s, pos)
        if rule.day > 365:
            raise ValueError(f"Day of year must be 0-365, got {rule.day}")

    else:
        raise ValueError(f"Expected DST rule (M, J, or digit), got '{s[pos]}'")

    # Parse optional /time suffix
    rule.time_seconds = 2 * 3600  # Default 02:00
    if pos < len(s) and s[pos] == "/":
        pos += 1
        rule.time_seconds, pos = _parse_offset(s, pos)

    return rule, pos


def parse_posix_tz(tz_string: str) -> ParsedTimezone:
    """Parse a POSIX TZ string into a ParsedTimezone struct.

    Supports formats like:
      - "EST5" (simple offset, no DST)
      - "EST5EDT,M3.2.0,M11.1.0" (with DST, M-format rules)
      - "CST6CDT,M3.2.0/2,M11.1.0/2" (with transition times)
      - "<+07>-7" (angle-bracket notation for special names)
      - "IST-5:30" (half-hour offsets)
      - "EST5EDT,J60,J300" (J-format: Julian day without leap day)
      - "EST5EDT,60,300" (plain day number: day of year with leap day)

    Args:
        tz_string: The POSIX TZ string to parse.

    Returns:
        ParsedTimezone with all fields populated.

    Raises:
        ValueError: If the string is empty or has invalid format.
    """
    if not tz_string:
        raise ValueError("Empty timezone string")

    result = ParsedTimezone()
    pos = 0

    # Skip standard timezone name
    pos = _skip_tz_name(tz_string, pos)

    # Parse standard offset (required)
    if pos >= len(tz_string) or (
        not tz_string[pos].isdigit() and tz_string[pos] != "+" and tz_string[pos] != "-"
    ):
        raise ValueError("Expected offset after timezone name")
    result.std_offset_seconds, pos = _parse_offset(tz_string, pos)

    # Check for DST name
    if pos >= len(tz_string):
        return result  # No DST

    # If next char is comma, there's no DST name but there are rules (invalid)
    if tz_string[pos] == ",":
        raise ValueError("Comma after standard offset without DST name")

    # Check if there's something that looks like a DST name start
    if not tz_string[pos].isalpha() and tz_string[pos] != "<":
        return result  # No DST, trailing characters ignored

    pos = _skip_tz_name(tz_string, pos)

    # Optional DST offset (default is std - 1 hour)
    if (
        pos < len(tz_string)
        and tz_string[pos] != ","
        and (tz_string[pos].isdigit() or tz_string[pos] in ("+", "-"))
    ):
        result.dst_offset_seconds, pos = _parse_offset(tz_string, pos)
    else:
        result.dst_offset_seconds = result.std_offset_seconds - 3600

    # Parse DST rules (required when DST name is present)
    if pos >= len(tz_string) or tz_string[pos] != ",":
        # DST name without rules - treat as no DST
        return result

    pos += 1
    result.dst_start, pos = _parse_dst_rule(tz_string, pos)

    # Second rule is required per POSIX
    if pos >= len(tz_string) or tz_string[pos] != ",":
        raise ValueError("Expected comma before second DST rule")
    pos += 1
    result.dst_end, pos = _parse_dst_rule(tz_string, pos)

    return result
