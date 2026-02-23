"""Tests for the POSIX TZ string parser.

Test cases ported from ESPHome's C++ test suite
(tests/components/time/posix_tz_parser.cpp) to ensure identical behavior.
"""

from __future__ import annotations

import pytest

from aioesphomeapi.posix_tz import DSTRuleType, ParsedTimezone, parse_posix_tz

# ============================================================================
# Basic TZ string parsing tests
# ============================================================================


def test_parse_simple_offset_est5() -> None:
    tz = parse_posix_tz("EST5")
    assert tz.std_offset_seconds == 5 * 3600  # +5 hours (west of UTC)
    assert not tz.has_dst


def test_parse_negative_offset_cet() -> None:
    tz = parse_posix_tz("CET-1")
    assert tz.std_offset_seconds == -1 * 3600  # -1 hour (east of UTC)
    assert not tz.has_dst


def test_parse_explicit_positive_offset() -> None:
    tz = parse_posix_tz("TEST+5")
    assert tz.std_offset_seconds == 5 * 3600
    assert not tz.has_dst


def test_parse_zero_offset() -> None:
    tz = parse_posix_tz("UTC0")
    assert tz.std_offset_seconds == 0
    assert not tz.has_dst


def test_parse_us_eastern_with_dst() -> None:
    tz = parse_posix_tz("EST5EDT,M3.2.0,M11.1.0")
    assert tz.std_offset_seconds == 5 * 3600
    assert tz.dst_offset_seconds == 4 * 3600  # Default: STD - 1hr
    assert tz.has_dst
    assert tz.dst_start.month == 3
    assert tz.dst_start.week == 2
    assert tz.dst_start.day_of_week == 0  # Sunday
    assert tz.dst_start.time_seconds == 2 * 3600  # Default 2:00 AM
    assert tz.dst_end.month == 11
    assert tz.dst_end.week == 1
    assert tz.dst_end.day_of_week == 0


def test_parse_us_central_with_time() -> None:
    tz = parse_posix_tz("CST6CDT,M3.2.0/2,M11.1.0/2")
    assert tz.std_offset_seconds == 6 * 3600
    assert tz.dst_offset_seconds == 5 * 3600
    assert tz.dst_start.time_seconds == 2 * 3600  # 2:00 AM
    assert tz.dst_end.time_seconds == 2 * 3600


def test_parse_europe_berlin() -> None:
    tz = parse_posix_tz("CET-1CEST,M3.5.0,M10.5.0/3")
    assert tz.std_offset_seconds == -1 * 3600
    assert tz.dst_offset_seconds == -2 * 3600  # Default: STD - 1hr
    assert tz.has_dst
    assert tz.dst_start.month == 3
    assert tz.dst_start.week == 5  # Last week
    assert tz.dst_end.month == 10
    assert tz.dst_end.week == 5  # Last week
    assert tz.dst_end.time_seconds == 3 * 3600  # 3:00 AM


def test_parse_new_zealand() -> None:
    tz = parse_posix_tz("NZST-12NZDT,M9.5.0,M4.1.0/3")
    assert tz.std_offset_seconds == -12 * 3600
    assert tz.dst_offset_seconds == -13 * 3600  # Default: STD - 1hr
    assert tz.has_dst
    assert tz.dst_start.month == 9  # September
    assert tz.dst_end.month == 4  # April


def test_parse_explicit_dst_offset() -> None:
    tz = parse_posix_tz("TEST5DST4,M3.2.0,M11.1.0")
    assert tz.std_offset_seconds == 5 * 3600
    assert tz.dst_offset_seconds == 4 * 3600
    assert tz.has_dst


# ============================================================================
# Angle-bracket notation tests
# ============================================================================


def test_parse_angle_bracket_positive() -> None:
    tz = parse_posix_tz("<+07>-7")
    assert tz.std_offset_seconds == -7 * 3600  # -7 = 7 hours east of UTC
    assert not tz.has_dst


def test_parse_angle_bracket_negative() -> None:
    tz = parse_posix_tz("<-03>3")
    assert tz.std_offset_seconds == 3 * 3600
    assert not tz.has_dst


def test_parse_angle_bracket_with_dst() -> None:
    tz = parse_posix_tz("<+10>-10<+11>,M10.1.0,M4.1.0/3")
    assert tz.std_offset_seconds == -10 * 3600
    assert tz.dst_offset_seconds == -11 * 3600
    assert tz.has_dst
    assert tz.dst_start.month == 10
    assert tz.dst_end.month == 4


def test_parse_angle_bracket_named() -> None:
    tz = parse_posix_tz("<AEST>-10")
    assert tz.std_offset_seconds == -10 * 3600
    assert not tz.has_dst


def test_parse_angle_bracket_with_minutes() -> None:
    tz = parse_posix_tz("<+0545>-5:45")
    assert tz.std_offset_seconds == -(5 * 3600 + 45 * 60)
    assert not tz.has_dst


# ============================================================================
# Half-hour and unusual offset tests
# ============================================================================


def test_parse_offset_india() -> None:
    tz = parse_posix_tz("IST-5:30")
    assert tz.std_offset_seconds == -(5 * 3600 + 30 * 60)
    assert not tz.has_dst


def test_parse_offset_nepal() -> None:
    tz = parse_posix_tz("NPT-5:45")
    assert tz.std_offset_seconds == -(5 * 3600 + 45 * 60)
    assert not tz.has_dst


def test_parse_offset_with_seconds() -> None:
    tz = parse_posix_tz("TEST-1:30:30")
    assert tz.std_offset_seconds == -(1 * 3600 + 30 * 60 + 30)


def test_parse_chatham_islands() -> None:
    tz = parse_posix_tz("<+1245>-12:45<+1345>,M9.5.0/2:45,M4.1.0/3:45")
    assert tz.std_offset_seconds == -(12 * 3600 + 45 * 60)
    assert tz.dst_offset_seconds == -(13 * 3600 + 45 * 60)
    assert tz.has_dst


def test_parse_max_offset_14_hours() -> None:
    tz = parse_posix_tz("<+14>-14")
    assert tz.std_offset_seconds == -14 * 3600


def test_parse_max_negative_offset_12_hours() -> None:
    tz = parse_posix_tz("<-12>12")
    assert tz.std_offset_seconds == 12 * 3600


# ============================================================================
# Invalid input tests
# ============================================================================


def test_parse_empty_string_fails() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("")


def test_parse_short_name_fails() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("AB5")


def test_parse_missing_offset_fails() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST")


def test_parse_unterminated_bracket_fails() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("<+07-7")


def test_parse_comma_without_dst_name_fails() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5,M3.2.0,M11.1.0")


# ============================================================================
# J-format and plain day number tests
# ============================================================================


def test_parse_j_format_basic() -> None:
    tz = parse_posix_tz("EST5EDT,J60,J305")
    assert tz.has_dst
    assert tz.dst_start.type == DSTRuleType.JULIAN_NO_LEAP
    assert tz.dst_start.day == 60
    assert tz.dst_end.type == DSTRuleType.JULIAN_NO_LEAP
    assert tz.dst_end.day == 305


def test_parse_j_format_with_time() -> None:
    tz = parse_posix_tz("EST5EDT,J60/2,J305/2")
    assert tz.dst_start.day == 60
    assert tz.dst_start.time_seconds == 2 * 3600
    assert tz.dst_end.day == 305
    assert tz.dst_end.time_seconds == 2 * 3600


def test_parse_plain_day_number() -> None:
    tz = parse_posix_tz("EST5EDT,59,304")
    assert tz.has_dst
    assert tz.dst_start.type == DSTRuleType.DAY_OF_YEAR
    assert tz.dst_start.day == 59
    assert tz.dst_end.type == DSTRuleType.DAY_OF_YEAR
    assert tz.dst_end.day == 304


def test_parse_j_format_invalid_day_zero() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,J0,J305")


def test_parse_j_format_invalid_day_366() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,J366,J305")


def test_parse_plain_day_with_time() -> None:
    tz = parse_posix_tz("EST5EDT,59/3,304/1:30")
    assert tz.dst_start.day == 59
    assert tz.dst_start.time_seconds == 3 * 3600
    assert tz.dst_end.day == 304
    assert tz.dst_end.time_seconds == 1 * 3600 + 30 * 60


def test_parse_plain_day_invalid_366() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,366,304")


# ============================================================================
# Transition time edge cases
# ============================================================================


def test_parse_negative_transition_time() -> None:
    tz = parse_posix_tz("EST5EDT,M3.2.0/-1,M11.1.0/2")
    assert tz.dst_start.time_seconds == -1 * 3600
    assert tz.dst_end.time_seconds == 2 * 3600


def test_parse_negative_transition_time_with_minutes() -> None:
    tz = parse_posix_tz("EST5EDT,M3.2.0/-1:30,M11.1.0")
    assert tz.dst_start.time_seconds == -(1 * 3600 + 30 * 60)


def test_parse_large_transition_time() -> None:
    tz = parse_posix_tz("EST5EDT,M3.2.0/25,M11.1.0")
    assert tz.dst_start.time_seconds == 25 * 3600


def test_parse_max_transition_time_167_hours() -> None:
    tz = parse_posix_tz("EST5EDT,M3.2.0/167,M11.1.0")
    assert tz.dst_start.time_seconds == 167 * 3600


def test_parse_transition_time_hours_minutes_seconds() -> None:
    tz = parse_posix_tz("EST5EDT,M3.2.0/2:30:45,M11.1.0")
    assert tz.dst_start.time_seconds == 2 * 3600 + 30 * 60 + 45


# ============================================================================
# Invalid M format tests
# ============================================================================


def test_parse_m_format_invalid_month_13() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,M13.1.0,M11.1.0")


def test_parse_m_format_invalid_month_0() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,M0.1.0,M11.1.0")


def test_parse_m_format_invalid_week_6() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,M3.6.0,M11.1.0")


def test_parse_m_format_invalid_week_0() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,M3.0.0,M11.1.0")


def test_parse_m_format_invalid_day_of_week_7() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,M3.2.7,M11.1.0")


def test_parse_missing_end_rule() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,M3.2.0")


def test_parse_missing_end_rule_j_format() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,J60")


def test_parse_missing_end_rule_plain_day() -> None:
    with pytest.raises(ValueError):
        parse_posix_tz("EST5EDT,60")


# ============================================================================
# Lowercase format tests
# ============================================================================


def test_parse_lowercase_m_format() -> None:
    tz = parse_posix_tz("EST5EDT,m3.2.0,m11.1.0")
    assert tz.has_dst
    assert tz.dst_start.month == 3
    assert tz.dst_end.month == 11


def test_parse_lowercase_j_format() -> None:
    tz = parse_posix_tz("EST5EDT,j60,j305")
    assert tz.dst_start.type == DSTRuleType.JULIAN_NO_LEAP
    assert tz.dst_start.day == 60


# ============================================================================
# DST name edge cases
# ============================================================================


def test_parse_dst_name_without_rules() -> None:
    """DST name present but no rules - treat as no DST."""
    tz = parse_posix_tz("EST5EDT")
    assert not tz.has_dst
    assert tz.std_offset_seconds == 5 * 3600


def test_parse_trailing_characters_ignored() -> None:
    """Trailing characters after valid TZ should be ignored."""
    tz = parse_posix_tz("EST5 extra garbage here")
    assert tz.std_offset_seconds == 5 * 3600
    assert not tz.has_dst


# ============================================================================
# Default values tests
# ============================================================================


def test_default_dst_rule_fields() -> None:
    """DSTRule with type=NONE should have zero fields."""
    tz = parse_posix_tz("EST5")
    assert tz.dst_start.type == DSTRuleType.NONE
    assert tz.dst_start.time_seconds == 0
    assert tz.dst_start.day == 0
    assert tz.dst_start.month == 0
    assert tz.dst_start.week == 0
    assert tz.dst_start.day_of_week == 0
    assert tz.dst_end.type == DSTRuleType.NONE


def test_default_transition_time_2am() -> None:
    """M-format without /time should default to 2:00 AM."""
    tz = parse_posix_tz("EST5EDT,M3.2.0,M11.1.0")
    assert tz.dst_start.time_seconds == 2 * 3600
    assert tz.dst_end.time_seconds == 2 * 3600


def test_dst_rule_type_enum_values() -> None:
    """Verify DSTRuleType enum matches C++ values."""
    assert DSTRuleType.NONE == 0
    assert DSTRuleType.MONTH_WEEK_DAY == 1
    assert DSTRuleType.JULIAN_NO_LEAP == 2
    assert DSTRuleType.DAY_OF_YEAR == 3


def test_parsed_timezone_default() -> None:
    """Default ParsedTimezone should be UTC with no DST."""
    tz: ParsedTimezone = ParsedTimezone()
    assert tz.std_offset_seconds == 0
    assert tz.dst_offset_seconds == 0
    assert not tz.has_dst


# ============================================================================
# Real-world timezone strings (from tzdata)
# ============================================================================


def test_parse_america_new_york() -> None:
    tz = parse_posix_tz("EST5EDT,M3.2.0,M11.1.0")
    assert tz.std_offset_seconds == 5 * 3600
    assert tz.dst_offset_seconds == 4 * 3600
    assert tz.dst_start.type == DSTRuleType.MONTH_WEEK_DAY
    assert tz.dst_start.month == 3
    assert tz.dst_start.week == 2
    assert tz.dst_start.day_of_week == 0
    assert tz.dst_end.month == 11
    assert tz.dst_end.week == 1


def test_parse_europe_london() -> None:
    tz = parse_posix_tz("GMT0BST,M3.5.0/1,M10.5.0")
    assert tz.std_offset_seconds == 0
    assert tz.dst_offset_seconds == -3600
    assert tz.dst_start.month == 3
    assert tz.dst_start.week == 5
    assert tz.dst_start.time_seconds == 1 * 3600  # 1:00 AM
    assert tz.dst_end.month == 10
    assert tz.dst_end.time_seconds == 2 * 3600  # Default 2:00 AM


def test_parse_asia_tokyo() -> None:
    tz = parse_posix_tz("JST-9")
    assert tz.std_offset_seconds == -9 * 3600
    assert not tz.has_dst


def test_parse_australia_sydney() -> None:
    tz = parse_posix_tz("AEST-10AEDT,M10.1.0,M4.1.0/3")
    assert tz.std_offset_seconds == -10 * 3600
    assert tz.dst_offset_seconds == -11 * 3600
    assert tz.dst_start.month == 10
    assert tz.dst_end.month == 4
    assert tz.dst_end.time_seconds == 3 * 3600


def test_parse_pacific_auckland() -> None:
    tz = parse_posix_tz("NZST-12NZDT,M9.5.0,M4.1.0/3")
    assert tz.std_offset_seconds == -12 * 3600
    assert tz.dst_offset_seconds == -13 * 3600
    assert tz.dst_start.month == 9
    assert tz.dst_end.month == 4


def test_parse_america_chicago() -> None:
    tz = parse_posix_tz("CST6CDT,M3.2.0,M11.1.0")
    assert tz.std_offset_seconds == 6 * 3600
    assert tz.dst_offset_seconds == 5 * 3600


def test_parse_asia_kolkata() -> None:
    tz = parse_posix_tz("IST-5:30")
    assert tz.std_offset_seconds == -(5 * 3600 + 30 * 60)
    assert not tz.has_dst
