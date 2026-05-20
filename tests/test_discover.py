from __future__ import annotations

from aioesphomeapi.discover import UNKNOWN, decode_bytes_or_unknown


def test_decode_bytes_or_unknown_none() -> None:
    assert decode_bytes_or_unknown(None) == UNKNOWN


def test_decode_bytes_or_unknown_str_passthrough() -> None:
    assert decode_bytes_or_unknown("esp32-board") == "esp32-board"


def test_decode_bytes_or_unknown_bytes_utf8() -> None:
    assert decode_bytes_or_unknown(b"esp32-board") == "esp32-board"


def test_decode_bytes_or_unknown_invalid_utf8_does_not_raise() -> None:
    # Hostile mDNS broadcaster sends non-UTF-8 bytes; result is sanitized to
    # printable characters, never raises UnicodeDecodeError.
    result = decode_bytes_or_unknown(b"\xff\xfe")
    assert isinstance(result, str)


def test_decode_bytes_or_unknown_strips_control_chars() -> None:
    # Strip the ESC byte that activates ANSI sequences, plus newline / CR /
    # null / tab / etc. The trailing "[2J" is harmless printable text once
    # the leading ESC is gone, so a hostile broadcaster can no longer clear
    # the user's terminal from a discovery scan.
    assert decode_bytes_or_unknown(b"\x1b[2Jvers\n1.0") == "[2Jvers1.0"
    assert decode_bytes_or_unknown(b"line1\r\nline2") == "line1line2"
    assert decode_bytes_or_unknown(b"col\tumn") == "column"


def test_decode_bytes_or_unknown_strips_null_byte() -> None:
    assert decode_bytes_or_unknown(b"esp\x0032") == "esp32"


def test_decode_bytes_or_unknown_caps_length() -> None:
    assert decode_bytes_or_unknown(b"x" * 200, limit=10) == "x" * 10


def test_decode_bytes_or_unknown_default_limit_caps_long_str() -> None:
    # Default MAX_NAME_LEN = 32.
    assert len(decode_bytes_or_unknown("a" * 100)) == 32


def test_decode_bytes_or_unknown_unicode_printable_survives() -> None:
    # safe_label_str uses str.isprintable so non-ASCII printable chars stay.
    assert decode_bytes_or_unknown("café") == "café"
