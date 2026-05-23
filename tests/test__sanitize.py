"""Tests for the peer-supplied label sanitizer."""

import pytest

from aioesphomeapi._sanitize import (
    MAX_EXPLANATION_LEN,
    MAX_MAC_LEN,
    MAX_NAME_LEN,
    safe_label_str,
)

# Control characters a hostile remote could embed in a name/server_info field
# to drive the operator's terminal or corrupt log lines.
_CONTROL_CHARS = ["\x1b", "\n", "\r", "\t", "\x00", "\x07", "\x7f", "\x08"]


@pytest.mark.parametrize("ctrl", _CONTROL_CHARS)
def test_control_chars_are_stripped(ctrl: str) -> None:
    """Each non-printable control char is removed from the output."""
    assert safe_label_str(f"a{ctrl}b", MAX_NAME_LEN) == "ab"


def test_ansi_escape_introducer_removed() -> None:
    """The ESC byte is stripped, neutralizing the escape sequence.

    The trailing ``[31m`` bytes are printable and remain, but without the
    leading ESC the terminal renders them as inert text rather than colour
    codes — that is the security property being pinned.
    """
    out = safe_label_str("\x1b[31mred\x1b[0m", MAX_NAME_LEN)
    assert "\x1b" not in out
    assert out == "[31mred[0m"


def test_printable_content_passes_through() -> None:
    """A clean label with spaces is returned unchanged."""
    assert safe_label_str("living room sensor", MAX_NAME_LEN) == "living room sensor"


def test_printable_unicode_is_retained() -> None:
    """Non-ASCII printable characters are kept, not flattened to ASCII."""
    assert safe_label_str("café 😀", MAX_NAME_LEN) == "café 😀"


def test_length_cap_applied_after_sanitization() -> None:
    """The cap counts sanitized characters, not the raw (padded) length."""
    # Two ESC bytes are stripped first, then "abc"[:2] -> "ab".
    assert safe_label_str("a\x1b\x1bbc", 2) == "ab"


def test_limit_truncates_printable_input() -> None:
    """A printable string longer than the limit is cut to the limit."""
    assert safe_label_str("abcdef", 3) == "abc"


def test_zero_limit_yields_empty() -> None:
    """A zero limit produces an empty string."""
    assert safe_label_str("anything", 0) == ""


def test_empty_input_yields_empty() -> None:
    """An empty input produces an empty string."""
    assert safe_label_str("", MAX_NAME_LEN) == ""


def test_all_non_printable_yields_empty() -> None:
    """A string of only control characters sanitizes to empty."""
    assert safe_label_str("\x00\x01\x02\x1b", MAX_NAME_LEN) == ""


@pytest.mark.parametrize("limit", [MAX_NAME_LEN, MAX_MAC_LEN, MAX_EXPLANATION_LEN])
def test_output_is_bounded_and_printable(limit: int) -> None:
    """For any documented cap, output stays printable and within the cap."""
    hostile = ("\x1b[2J" + "x" * 200 + "\nmore\ttext\x00") * 4
    out = safe_label_str(hostile, limit)
    assert len(out) <= limit
    assert out.isprintable()
