"""Tests for the log parser module."""

from __future__ import annotations

from aioesphomeapi.log_parser import parse_log_message


def test_single_line_no_color() -> None:
    """Test parsing a single line log without color codes."""
    text = (
        "[I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30"
    )
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert isinstance(result, list)
    assert len(result) == 1
    assert (
        result[0]
        == "[08:00:00.000][I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30"
    )


def test_single_line_with_color() -> None:
    """Test parsing a single line log with ANSI color codes."""
    text = "\033[0;32m[I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30\033[0m"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert isinstance(result, list)
    assert len(result) == 1
    assert (
        result[0]
        == "[08:00:00.000]\033[0;32m[I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30\033[0m"
    )


def test_multi_line_no_color() -> None:
    """Test parsing a multi-line log without color codes."""
    text = "[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'\n  State Class: ''\n  Unit of Measurement: ''\n  Accuracy Decimals: 1"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert isinstance(result, list)
    assert len(result) == 4
    assert (
        result[0]
        == "[08:00:00.000][C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'"
    )
    assert result[1] == "[08:00:00.000][C][template.sensor:022]:   State Class: ''"
    assert (
        result[2] == "[08:00:00.000][C][template.sensor:022]:   Unit of Measurement: ''"
    )
    assert result[3] == "[08:00:00.000][C][template.sensor:022]:   Accuracy Decimals: 1"


def test_multi_line_with_color() -> None:
    """Test parsing a multi-line log with ANSI color codes."""
    text = "\033[0;35m[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'\n  State Class: ''\n  Unit of Measurement: ''\n  Accuracy Decimals: 1\033[0m"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert isinstance(result, list)
    assert len(result) == 4
    assert (
        result[0]
        == "[08:00:00.000]\033[0;35m[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'"
    )
    assert (
        result[1]
        == "[08:00:00.000]\033[0;35m[C][template.sensor:022]:   State Class: ''\033[0m"
    )
    assert (
        result[2]
        == "[08:00:00.000]\033[0;35m[C][template.sensor:022]:   Unit of Measurement: ''\033[0m"
    )
    assert (
        result[3]
        == "[08:00:00.000]\033[0;35m[C][template.sensor:022]:   Accuracy Decimals: 1\033[0m"
    )


def test_multi_line_with_empty_lines() -> None:
    """Test parsing a multi-line log with empty lines."""
    text = "[C][logger:224]: Logger:\n\n  Max Level: DEBUG\n  Initial Level: DEBUG"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert isinstance(result, list)
    assert len(result) == 4
    assert result[0] == "[08:00:00.000][C][logger:224]: Logger:"
    assert result[1] == ""  # Empty line
    # The prefix extraction finds "Logger:" not "[C][logger:224]:" so no prefix is added
    assert result[2] == "[08:00:00.000]  Max Level: DEBUG"
    assert result[3] == "[08:00:00.000]  Initial Level: DEBUG"


def test_multi_line_mixed_entries() -> None:
    """Test parsing multiple log entries in one message."""
    text = "[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'\n  State Class: ''\n[C][template.sensor:023]:   Update Interval: 60.0s"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert isinstance(result, list)
    assert len(result) == 3
    assert (
        result[0]
        == "[08:00:00.000][C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'"
    )
    assert result[1] == "[08:00:00.000][C][template.sensor:022]:   State Class: ''"
    assert (
        result[2] == "[08:00:00.000][C][template.sensor:023]:   Update Interval: 60.0s"
    )


def test_prefix_extraction_edge_cases() -> None:
    """Test edge cases for prefix extraction."""
    # No prefix found
    text = "Simple log message\n  Continuation"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 2
    assert result[0] == "[08:00:00.000]Simple log message"
    assert result[1] == "[08:00:00.000]  Continuation"


def test_various_ansi_codes() -> None:
    """Test parsing with various ANSI escape sequences."""
    # Bold green
    text = "\033[1;32m[I][test:001]: Bold green message\033[0m"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 1
    assert (
        result[0] == "[08:00:00.000]\033[1;32m[I][test:001]: Bold green message\033[0m"
    )

    # Complex escape sequence
    text = "\033[38;5;214m[W][test:002]: 256-color warning\n  Details\033[0m"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 2
    assert result[0] == "[08:00:00.000]\033[38;5;214m[W][test:002]: 256-color warning"
    assert result[1] == "[08:00:00.000]\033[38;5;214m[W][test:002]:   Details\033[0m"


def test_empty_message() -> None:
    """Test parsing an empty message."""
    text = ""
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 1
    assert result[0] == "[08:00:00.000]"


def test_only_newlines() -> None:
    """Test parsing a message with only newlines."""
    text = "\n\n\n"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    # Three newlines create 4 parts when split, but last empty one is removed
    assert len(result) == 3
    assert result[0] == "[08:00:00.000]"
    assert all(line == "" for line in result[1:])


def test_continuation_without_prefix() -> None:
    """Test continuation lines when no prefix is found."""
    text = "Main line\n  Sub line 1\n  Sub line 2"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 3
    assert result[0] == "[08:00:00.000]Main line"
    assert result[1] == "[08:00:00.000]  Sub line 1"
    assert result[2] == "[08:00:00.000]  Sub line 2"


def test_real_world_example() -> None:
    """Test with a real-world log example."""
    text = "\033[0;35m[C][uptime.sensor:033]: Uptime Sensor 'Ethernet Uptime'\n  State Class: 'total_increasing'\n  Unit of Measurement: 's'\n  Accuracy Decimals: 0\033[0m"
    timestamp = "[07:56:42.728]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 4
    assert (
        result[0]
        == "[07:56:42.728]\033[0;35m[C][uptime.sensor:033]: Uptime Sensor 'Ethernet Uptime'"
    )
    assert (
        result[1]
        == "[07:56:42.728]\033[0;35m[C][uptime.sensor:033]:   State Class: 'total_increasing'\033[0m"
    )
    assert (
        result[2]
        == "[07:56:42.728]\033[0;35m[C][uptime.sensor:033]:   Unit of Measurement: 's'\033[0m"
    )
    assert (
        result[3]
        == "[07:56:42.728]\033[0;35m[C][uptime.sensor:033]:   Accuracy Decimals: 0\033[0m"
    )


def test_timestamp_formats() -> None:
    """Test with different timestamp formats."""
    text = "[I][test:001]: Test message"

    # Standard format
    result = parse_log_message(text, "[08:00:00.000]")
    assert result[0] == "[08:00:00.000][I][test:001]: Test message"

    # Custom format
    result = parse_log_message(text, "[2024-01-01 08:00:00]")
    assert result[0] == "[2024-01-01 08:00:00][I][test:001]: Test message"

    # Empty timestamp
    result = parse_log_message(text, "")
    assert result[0] == "[I][test:001]: Test message"


def test_trailing_newline() -> None:
    """Test handling of messages that end with a newline."""
    # Single line with trailing newline
    text = "[I][app:191]: ESPHome version 2025.6.0\n"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    # Should not include an empty line at the end
    assert len(result) == 1
    assert result[0] == "[08:00:00.000][I][app:191]: ESPHome version 2025.6.0"

    # Multi-line with trailing newline (no ESPHome prefix found since "Config" doesn't end with ]:")
    text = "[C][sensor:022]: Sensor Config\n  State: ON\n"
    result = parse_log_message(text, timestamp)

    assert len(result) == 2
    assert result[0] == "[08:00:00.000][C][sensor:022]: Sensor Config"
    assert result[1] == "[08:00:00.000]  State: ON"

    # With proper ESPHome prefix format
    text = "[C][sensor:022]: Temperature Sensor 'Living Room'\n  State Class: 'measurement'\n"
    result = parse_log_message(text, timestamp)

    assert len(result) == 2
    assert (
        result[0] == "[08:00:00.000][C][sensor:022]: Temperature Sensor 'Living Room'"
    )
    assert result[1] == "[08:00:00.000][C][sensor:022]:   State Class: 'measurement'"

    # With color codes ending with reset on its own line
    text = "\033[0;35m[C][sensor:022]: Temperature Sensor\n  State: ON\n\033[0m"
    result = parse_log_message(text, timestamp)

    # Should not include the line with just the reset code
    assert len(result) == 2
    assert result[0] == "[08:00:00.000]\033[0;35m[C][sensor:022]: Temperature Sensor"
    assert result[1] == "[08:00:00.000]\033[0;35m[C][sensor:022]:   State: ON\033[0m"


def test_strip_ansi_escapes() -> None:
    """Test stripping ANSI escape sequences."""
    # Single line with color
    text = "\033[0;32m[I][app:191]: ESPHome version 2025.6.0-dev\033[0m"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp, strip_ansi_escapes=True)

    assert len(result) == 1
    assert result[0] == "[08:00:00.000][I][app:191]: ESPHome version 2025.6.0-dev"

    # Multi-line with color
    text = "\033[0;35m[C][sensor:022]: Temperature Sensor\n  State: ON\n  Value: 23.5\033[0m"
    result = parse_log_message(text, timestamp, strip_ansi_escapes=True)

    assert len(result) == 3
    assert result[0] == "[08:00:00.000][C][sensor:022]: Temperature Sensor"
    assert result[1] == "[08:00:00.000][C][sensor:022]:   State: ON"
    assert result[2] == "[08:00:00.000][C][sensor:022]:   Value: 23.5"

    # Complex nested colors (BLE logs)
    text = "\033[0;36m[D][esp-idf:000]\033[1;31m[BTU_TASK]\033[0;36m: \033[0;33mW (2335697) BT_APPL: gattc_conn_cb\033[0m\033[0m"
    result = parse_log_message(text, timestamp, strip_ansi_escapes=True)

    assert len(result) == 1
    assert (
        result[0]
        == "[08:00:00.000][D][esp-idf:000][BTU_TASK]: W (2335697) BT_APPL: gattc_conn_cb"
    )


def test_first_line_starts_with_space() -> None:
    """Test edge case where first line starts with space."""
    text = "  First line starts with space\n  Second line also starts with space\nNot a continuation"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 3
    assert result[0] == "[08:00:00.000]  First line starts with space"
    assert result[1] == "[08:00:00.000]  Second line also starts with space"
    assert result[2] == "[08:00:00.000]Not a continuation"


def test_first_line_starts_with_space_with_color() -> None:
    """Test edge case where first line starts with space and has ANSI color."""
    text = "\033[0;32m  Colored line starting with space\n  Another continuation\033[0m"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 2
    assert result[0] == "[08:00:00.000]\033[0;32m  Colored line starting with space"
    assert result[1] == "[08:00:00.000]\033[0;32m  Another continuation\033[0m"
