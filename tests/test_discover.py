from __future__ import annotations

import re

from aioesphomeapi.discover import (
    _MAX_BOARD_DISPLAY,
    _MAX_MAC_DISPLAY,
    _MAX_NAME_DISPLAY,
    _MAX_PLATFORM_DISPLAY,
    _MAX_VERSION_DISPLAY,
    COLUMN_NAMES,
    FORMAT,
    UNKNOWN,
    decode_mdns_label_or_unknown,
)


def test_decode_mdns_label_or_unknown_none() -> None:
    assert decode_mdns_label_or_unknown(None) == UNKNOWN


def test_decode_mdns_label_or_unknown_str_passthrough() -> None:
    assert decode_mdns_label_or_unknown("esp32-board") == "esp32-board"


def test_decode_mdns_label_or_unknown_bytes_utf8() -> None:
    assert decode_mdns_label_or_unknown(b"esp32-board") == "esp32-board"


def test_decode_mdns_label_or_unknown_invalid_utf8_replaces() -> None:
    # Hostile mDNS broadcaster sends non-UTF-8 bytes; result is the U+FFFD
    # replacement character (one per invalid byte), never raises
    # UnicodeDecodeError. Pinning the actual output, not just the type, keeps
    # a future refactor from silently switching to UNKNOWN or empty string.
    assert decode_mdns_label_or_unknown(b"\xff\xfe") == "\ufffd\ufffd"


def test_decode_mdns_label_or_unknown_strips_control_chars() -> None:
    # Strip the ESC byte that activates ANSI sequences, plus newline / CR /
    # null / tab / etc. The trailing "[2J" is harmless printable text once
    # the leading ESC is gone, so a hostile broadcaster can no longer clear
    # the user's terminal from a discovery scan.
    assert decode_mdns_label_or_unknown(b"\x1b[2Jvers\n1.0") == "[2Jvers1.0"
    assert decode_mdns_label_or_unknown(b"line1\r\nline2") == "line1line2"
    assert decode_mdns_label_or_unknown(b"col\tumn") == "column"


def test_decode_mdns_label_or_unknown_strips_null_byte() -> None:
    assert decode_mdns_label_or_unknown(b"esp\x0032") == "esp32"


def test_decode_mdns_label_or_unknown_caps_length() -> None:
    assert decode_mdns_label_or_unknown(b"x" * 200, limit=10) == "x" * 10


def test_decode_mdns_label_or_unknown_default_limit_caps_long_str() -> None:
    # Default cap is the Name column width from FORMAT.
    assert len(decode_mdns_label_or_unknown("a" * 100)) == _MAX_NAME_DISPLAY


def test_decode_mdns_label_or_unknown_unicode_printable_survives() -> None:
    # safe_label_str uses str.isprintable so non-ASCII printable chars stay.
    assert decode_mdns_label_or_unknown("café") == "café"


def test_per_column_caps_match_format_widths() -> None:
    # The per-column caps must equal the FORMAT widths so a peer-controlled
    # value can never widen a column past its slot. If FORMAT changes and
    # this assertion fires, update the cap derivation in discover.py — do
    # not just bump the expected values.
    widths = tuple(int(w) for w in re.findall(r"<\s*(\d+)", FORMAT))
    assert widths[COLUMN_NAMES.index("Name")] == _MAX_NAME_DISPLAY
    assert widths[COLUMN_NAMES.index("MAC")] == _MAX_MAC_DISPLAY
    assert widths[COLUMN_NAMES.index("Version")] == _MAX_VERSION_DISPLAY
    assert widths[COLUMN_NAMES.index("Platform")] == _MAX_PLATFORM_DISPLAY
    assert widths[COLUMN_NAMES.index("Board")] == _MAX_BOARD_DISPLAY
