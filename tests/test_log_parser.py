"""Tests for the log parser module."""

from __future__ import annotations

from aioesphomeapi.log_parser import LogParser, parse_log_message


def test_single_line_no_color() -> None:
    """Test parsing a single line log without color codes."""
    text = (
        "[I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30"
    )
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert isinstance(result, (list, tuple))
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

    assert isinstance(result, (list, tuple))
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

    assert isinstance(result, (list, tuple))
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

    assert isinstance(result, (list, tuple))
    assert len(result) == 4
    assert (
        result[0]
        == "[08:00:00.000]\033[0;35m[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'\033[0m"
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

    assert isinstance(result, (list, tuple))
    assert len(result) == 4
    assert result[0] == "[08:00:00.000][C][logger:224]: Logger:"
    assert result[1] == ""  # Empty line
    assert result[2] == "[08:00:00.000][C][logger:224]:   Max Level: DEBUG"
    assert result[3] == "[08:00:00.000][C][logger:224]:   Initial Level: DEBUG"


def test_multi_line_mixed_entries() -> None:
    """Test parsing multiple log entries in one message."""
    text = "[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'\n  State Class: ''\n[C][template.sensor:023]:   Update Interval: 60.0s"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert isinstance(result, (list, tuple))
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
    assert (
        result[0]
        == "[08:00:00.000]\033[38;5;214m[W][test:002]: 256-color warning\033[0m"
    )
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
        == "[07:56:42.728]\033[0;35m[C][uptime.sensor:033]: Uptime Sensor 'Ethernet Uptime'\033[0m"
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

    # Multi-line with trailing newline
    text = "[C][sensor:022]: Sensor Config\n  State: ON\n"
    result = parse_log_message(text, timestamp)

    assert len(result) == 2
    assert result[0] == "[08:00:00.000][C][sensor:022]: Sensor Config"
    assert result[1] == "[08:00:00.000][C][sensor:022]:   State: ON"

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
    assert (
        result[0]
        == "[08:00:00.000]\033[0;35m[C][sensor:022]: Temperature Sensor\033[0m"
    )
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
    assert (
        result[0] == "[08:00:00.000]\033[0;32m  Colored line starting with space\033[0m"
    )
    assert result[1] == "[08:00:00.000]\033[0;32m  Another continuation\033[0m"


def test_newline_only_message() -> None:
    """Test edge case where message is just a newline."""
    text = "\n"
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    # Should handle gracefully - just timestamp with empty content
    assert len(result) == 1
    assert result[0] == "[08:00:00.000]"


def test_long_component_name_prefix() -> None:
    """Test that long component names are correctly extracted."""
    text = (
        "[C][really.long.component.name.sensor:123456]: Short message\n  Details here"
    )
    timestamp = "[08:00:00.000]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 2
    assert (
        result[0]
        == "[08:00:00.000][C][really.long.component.name.sensor:123456]: Short message"
    )
    assert (
        result[1]
        == "[08:00:00.000][C][really.long.component.name.sensor:123456]:   Details here"
    )


def test_color_bleeding_prevention() -> None:
    """Test that color codes don't bleed to next message when first line lacks reset."""
    # This simulates the issue where first line of multi-line
    # message has color but no reset, causing color to bleed to next message
    text = "\033[0;35m[C][template.sensor:022]: Template Sensor 'Free Memory'\n  State Class: 'measurement'\n  Unit of Measurement: 'B'\n  Accuracy Decimals: 1\033[0m"
    timestamp = "[09:05:25.545]"
    result = parse_log_message(text, timestamp)

    assert len(result) == 4
    # First line should have reset added to prevent bleeding
    assert (
        result[0]
        == "[09:05:25.545]\033[0;35m[C][template.sensor:022]: Template Sensor 'Free Memory'\033[0m"
    )
    assert (
        result[1]
        == "[09:05:25.545]\033[0;35m[C][template.sensor:022]:   State Class: 'measurement'\033[0m"
    )
    assert (
        result[2]
        == "[09:05:25.545]\033[0;35m[C][template.sensor:022]:   Unit of Measurement: 'B'\033[0m"
    )
    assert (
        result[3]
        == "[09:05:25.545]\033[0;35m[C][template.sensor:022]:   Accuracy Decimals: 1\033[0m"
    )


# Tests for LogParser


def test_logparser_single_line_no_color() -> None:
    """Test parsing a single line log without color codes."""
    parser = LogParser()
    line = (
        "[I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30"
    )
    timestamp = "[08:00:00.000]"
    result = parser.parse_line(line, timestamp)

    assert (
        result
        == "[08:00:00.000][I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30"
    )


def test_logparser_single_line_with_color() -> None:
    """Test parsing a single line log with ANSI color codes."""
    parser = LogParser()
    line = "\033[0;32m[I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30\033[0m"
    timestamp = "[08:00:00.000]"
    result = parser.parse_line(line, timestamp)

    assert (
        result
        == "[08:00:00.000]\033[0;32m[I][app:191]: ESPHome version 2025.6.0-dev compiled on Jun  8 2025, 07:48:30\033[0m"
    )


def test_logparser_multi_line_sequence() -> None:
    """Test parsing a multi-line log sequence line by line."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # First line establishes prefix and color
    line1 = "[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'"
    result1 = parser.parse_line(line1, timestamp)
    assert (
        result1
        == "[08:00:00.000][C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'"
    )

    # Continuation lines
    line2 = "  State Class: ''"
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == "[08:00:00.000][C][template.sensor:022]:   State Class: ''"

    line3 = "  Unit of Measurement: ''"
    result3 = parser.parse_line(line3, timestamp)
    assert (
        result3 == "[08:00:00.000][C][template.sensor:022]:   Unit of Measurement: ''"
    )

    line4 = "  Accuracy Decimals: 1"
    result4 = parser.parse_line(line4, timestamp)
    assert result4 == "[08:00:00.000][C][template.sensor:022]:   Accuracy Decimals: 1"


def test_logparser_multi_line_with_color_sequence() -> None:
    """Test parsing a multi-line log with color codes line by line."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # First line with color
    line1 = "\033[0;35m[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'"
    result1 = parser.parse_line(line1, timestamp)
    # Should add reset to prevent color bleeding
    assert (
        result1
        == "[08:00:00.000]\033[0;35m[C][template.sensor:022]: Template Sensor 'Lambda Sensor 153'\033[0m"
    )

    # Continuation lines should inherit color
    line2 = "  State Class: ''"
    result2 = parser.parse_line(line2, timestamp)
    assert (
        result2
        == "[08:00:00.000]\033[0;35m[C][template.sensor:022]:   State Class: ''\033[0m"
    )

    line3 = "  Unit of Measurement: ''"
    result3 = parser.parse_line(line3, timestamp)
    assert (
        result3
        == "[08:00:00.000]\033[0;35m[C][template.sensor:022]:   Unit of Measurement: ''\033[0m"
    )


def test_logparser_new_entry_resets_state() -> None:
    """Test that a new log entry resets the parser state."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # First multi-line entry with color
    line1 = "\033[0;35m[C][sensor:022]: Sensor 1"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000]\033[0;35m[C][sensor:022]: Sensor 1\033[0m"

    line2 = "  Details"
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == "[08:00:00.000]\033[0;35m[C][sensor:022]:   Details\033[0m"

    # New entry should reset state
    line3 = "[I][app:001]: Different message"
    result3 = parser.parse_line(line3, timestamp)
    assert result3 == "[08:00:00.000][I][app:001]: Different message"

    # Continuation of new entry should not have old prefix/color
    line4 = "  New details"
    result4 = parser.parse_line(line4, timestamp)
    assert result4 == "[08:00:00.000][I][app:001]:   New details"


def test_logparser_empty_lines() -> None:
    """Test handling of empty lines."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # Empty line as continuation
    line1 = "[C][logger:224]: Logger:"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000][C][logger:224]: Logger:"

    line2 = ""
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == ""

    line3 = "  Max Level: DEBUG"
    result3 = parser.parse_line(line3, timestamp)
    assert result3 == "[08:00:00.000][C][logger:224]:   Max Level: DEBUG"


def test_logparser_whitespace_only_continuation() -> None:
    """Test handling of whitespace-only continuation lines."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # First establish a log entry
    line1 = "[I][sensor:123]: Temperature sensor"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000][I][sensor:123]: Temperature sensor"

    # Whitespace-only continuation line (spaces)
    line2 = "    "
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == ""

    # Another whitespace-only continuation line (tabs)
    line3 = "\t\t"
    result3 = parser.parse_line(line3, timestamp)
    assert result3 == ""

    # Mix of spaces and tabs
    line4 = "  \t  "
    result4 = parser.parse_line(line4, timestamp)
    assert result4 == ""

    # Real continuation after whitespace
    line5 = "  Reading: 23.5°C"
    result5 = parser.parse_line(line5, timestamp)
    assert result5 == "[08:00:00.000][I][sensor:123]:   Reading: 23.5°C"


def test_logparser_whitespace_continuation_with_color() -> None:
    """Test whitespace-only continuation lines with color codes."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # First establish a colored log entry
    line1 = "\033[0;35m[C][wifi:123]: WiFi Component"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000]\033[0;35m[C][wifi:123]: WiFi Component\033[0m"

    # Whitespace-only continuation line should still return empty
    line2 = "  \t  "
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == ""

    # Real continuation should have color
    line3 = "  SSID: 'MyNetwork'"
    result3 = parser.parse_line(line3, timestamp)
    assert (
        result3 == "[08:00:00.000]\033[0;35m[C][wifi:123]:   SSID: 'MyNetwork'\033[0m"
    )


def test_logparser_strip_ansi_escapes() -> None:
    """Test stripping ANSI escape sequences."""
    parser = LogParser(strip_ansi_escapes=True)
    timestamp = "[08:00:00.000]"

    # Single line with color
    line1 = "\033[0;32m[I][app:191]: ESPHome version 2025.6.0-dev\033[0m"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000][I][app:191]: ESPHome version 2025.6.0-dev"

    # Multi-line with color
    line2 = "\033[0;35m[C][sensor:022]: Temperature Sensor"
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == "[08:00:00.000][C][sensor:022]: Temperature Sensor"

    line3 = "  State: ON"
    result3 = parser.parse_line(line3, timestamp)
    assert result3 == "[08:00:00.000][C][sensor:022]:   State: ON"


def test_logparser_line_with_trailing_newlines() -> None:
    """Test that trailing newlines are properly stripped."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # Line with \n
    line1 = "[I][app:001]: Test message\n"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000][I][app:001]: Test message"

    # Line with \r\n
    line2 = "[I][app:002]: Another message\r\n"
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == "[08:00:00.000][I][app:002]: Another message"


def test_logparser_continuation_without_prefix() -> None:
    """Test continuation lines when no prefix is found."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    line1 = "Main line without bracket-colon"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000]Main line without bracket-colon"

    line2 = "  Sub line"
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == "[08:00:00.000]  Sub line"


def test_logparser_lines_starting_with_space() -> None:
    """Test edge case where first line starts with space."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # First line starts with space - treated as new entry
    line1 = "  First line starts with space"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000]  First line starts with space"

    # Another line starting with space - treated as continuation
    line2 = "  Second line also starts with space"
    result2 = parser.parse_line(line2, timestamp)
    assert result2 == "[08:00:00.000]  Second line also starts with space"


def test_logparser_color_code_with_reset_at_end() -> None:
    """Test that lines already ending with reset don't get double reset."""
    parser = LogParser()
    timestamp = "[08:00:00.000]"

    # Line already has reset at end
    line1 = "\033[0;32m[I][test:001]: Message with reset\033[0m"
    result1 = parser.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000]\033[0;32m[I][test:001]: Message with reset\033[0m"

    # Continuation line with reset
    line2 = "  Continuation with reset\033[0m"
    result2 = parser.parse_line(line2, timestamp)
    assert (
        result2
        == "[08:00:00.000]\033[0;32m[I][test:001]:   Continuation with reset\033[0m"
    )


def test_logparser_real_world_serial_sequence() -> None:
    """Test with a real-world log sequence as it would come from streaming input."""
    parser = LogParser()

    # Simulate streaming input line by line
    lines = [
        (
            "\033[0;35m[C][uptime.sensor:033]: Uptime Sensor 'Ethernet Uptime'",
            "[07:56:42.728]",
        ),
        ("  State Class: 'total_increasing'", "[07:56:42.729]"),
        ("  Unit of Measurement: 's'", "[07:56:42.730]"),
        ("  Accuracy Decimals: 0", "[07:56:42.731]"),
        ("[I][app:191]: ESPHome version 2025.6.0-dev", "[07:56:42.732]"),
        (
            "\033[0;32m[D][sensor:094]: 'Living Room Temperature': Sending state 23.50000",
            "[07:56:42.733]",
        ),
    ]

    expected = [
        "[07:56:42.728]\033[0;35m[C][uptime.sensor:033]: Uptime Sensor 'Ethernet Uptime'\033[0m",
        "[07:56:42.729]\033[0;35m[C][uptime.sensor:033]:   State Class: 'total_increasing'\033[0m",
        "[07:56:42.730]\033[0;35m[C][uptime.sensor:033]:   Unit of Measurement: 's'\033[0m",
        "[07:56:42.731]\033[0;35m[C][uptime.sensor:033]:   Accuracy Decimals: 0\033[0m",
        "[07:56:42.732][I][app:191]: ESPHome version 2025.6.0-dev",
        "[07:56:42.733]\033[0;32m[D][sensor:094]: 'Living Room Temperature': Sending state 23.50000\033[0m",
    ]

    for i, (line, timestamp) in enumerate(lines):
        result = parser.parse_line(line, timestamp)
        assert result == expected[i]


def test_logparser_multiple_parsers_independent() -> None:
    """Test that multiple parser instances maintain independent state."""
    parser1 = LogParser()
    parser2 = LogParser(strip_ansi_escapes=True)

    timestamp = "[08:00:00.000]"

    # Parser 1 processes colored multi-line
    line1 = "\033[0;35m[C][sensor:001]: Sensor 1"
    result1 = parser1.parse_line(line1, timestamp)
    assert result1 == "[08:00:00.000]\033[0;35m[C][sensor:001]: Sensor 1\033[0m"

    # Parser 2 processes different entry
    line2 = "\033[0;32m[I][app:002]: App message"
    result2 = parser2.parse_line(line2, timestamp)
    assert result2 == "[08:00:00.000][I][app:002]: App message"  # No color due to strip

    # Continue with parser 1 - should maintain its state
    line3 = "  Details for sensor 1"
    result3 = parser1.parse_line(line3, timestamp)
    assert (
        result3
        == "[08:00:00.000]\033[0;35m[C][sensor:001]:   Details for sensor 1\033[0m"
    )

    # Continue with parser 2
    line4 = "  Details for app"
    result4 = parser2.parse_line(line4, timestamp)
    assert result4 == "[08:00:00.000][I][app:002]:   Details for app"
