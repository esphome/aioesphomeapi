"""Log parser for ESPHome log messages with ANSI color support."""

from __future__ import annotations

from collections.abc import Iterable
import re

# Pre-compiled regex for ANSI escape sequences
ANSI_ESCAPE = re.compile(
    r"(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])"
)

# ANSI reset sequences
ANSI_RESET_CODES = ("\033[0m", "\x1b[0m")
ANSI_RESET = "\033[0m"


def _extract_prefix_and_color(line: str, strip_ansi: bool) -> tuple[str, str, str]:
    """Extract ESPHome prefix and ANSI color code from line.

    Returns:
        Tuple of (prefix, color_code, line_without_color)
    """
    color_code = ""
    line_no_color = line

    # Extract ANSI color code at the beginning if present
    if not strip_ansi and (color_match := ANSI_ESCAPE.match(line)):
        color_code = color_match.group(0)
        line_no_color = line[len(color_code) :]

    # Find the ESPHome prefix
    bracket_colon = line_no_color.find("]:")
    prefix = line_no_color[: bracket_colon + 2] if bracket_colon != -1 else ""

    return prefix, color_code, line_no_color


def _needs_reset(line: str) -> bool:
    """Check if line needs ANSI reset code appended."""
    return bool(
        line
        and not line.endswith(ANSI_RESET_CODES)
        and ("\033[" in line or "\x1b[" in line)
    )


def _format_continuation_line(
    timestamp: str,
    prefix: str,
    line: str,
    color_code: str = "",
    strip_ansi: bool = False,
) -> str:
    """Format a continuation line with prefix and optional color."""
    line_content = f"{prefix} {line}" if prefix else line

    if color_code and not strip_ansi:
        reset = "" if line.endswith(ANSI_RESET_CODES) else ANSI_RESET
        return f"{timestamp}{color_code}{line_content}{reset}"

    return f"{timestamp}{line_content}"


class LogParser:
    """Stateful parser for processing log messages one line at a time.

    This parser is designed for streaming input where log messages come
    line by line rather than in complete multi-line blocks.
    """

    def __init__(self, strip_ansi_escapes: bool = False) -> None:
        """Initialize the parser.

        Args:
            strip_ansi_escapes: If True, remove all ANSI escape sequences from output
        """
        self.strip_ansi_escapes = strip_ansi_escapes
        self._current_prefix = ""
        self._current_color_code = ""

    def parse_line(self, line: str, timestamp: str) -> str:
        """Parse a single line and return formatted output.

        Args:
            line: A single line of log text (without newline)
            timestamp: The timestamp string to prepend (e.g., "[08:00:00.000]")

        Returns:
            Formatted line ready to be printed.
        """
        # Strip any trailing newline if present
        line = line.rstrip("\n\r")

        # Strip ANSI escapes if requested
        if self.strip_ansi_escapes:
            line = ANSI_ESCAPE.sub("", line)

        # Empty line handling
        if not line:
            return ""

        # Check if this is a new log entry or a continuation
        is_continuation = line[0].isspace()

        if not is_continuation:
            # This is a new log entry - update state
            self._current_prefix = ""
            self._current_color_code = ""

            # Extract prefix and color for potential multi-line messages
            if line and not line[0].isspace():
                self._current_prefix, self._current_color_code, _ = (
                    _extract_prefix_and_color(line, self.strip_ansi_escapes)
                )

            # Format the first line
            output = f"{timestamp}{line}"

            # Add reset if line has color but no reset at end
            if not self.strip_ansi_escapes and _needs_reset(line):
                output += ANSI_RESET

            return output

        # This is a continuation line
        if not line.strip():
            return ""

        return _format_continuation_line(
            timestamp,
            self._current_prefix,
            line,
            self._current_color_code,
            self.strip_ansi_escapes,
        )


def parse_log_message(
    text: str, timestamp: str, *, strip_ansi_escapes: bool = False
) -> Iterable[str]:
    """Parse a log message and format it with timestamps and color preservation.

    Args:
        text: The log message text, potentially with ANSI codes and newlines
        timestamp: The timestamp string to prepend (e.g., "[08:00:00.000]")
        strip_ansi_escapes: If True, remove all ANSI escape sequences from output

    Returns:
        Iterable of formatted lines ready to be printed.
        For single-line logs, returns a tuple for efficiency.
        For multi-line logs, returns a list.
    """
    # Strip ANSI escapes if requested
    if strip_ansi_escapes:
        text = ANSI_ESCAPE.sub("", text)

    # Fast path for single line (most common case)
    if "\n" not in text:
        return (f"{timestamp}{text}",)

    # Multi-line handling
    lines = text.split("\n")

    # Remove trailing empty line or ANSI reset codes
    if lines and (lines[-1] == "" or lines[-1] in ANSI_RESET_CODES):
        lines.pop()
    result: list[str] = []

    # Process the first line
    first_line_output = f"{timestamp}{lines[0]}"

    # Check if first line has color but no reset at end (to prevent bleeding)
    if not strip_ansi_escapes and _needs_reset(lines[0]):
        first_line_output += ANSI_RESET

    result.append(first_line_output)

    # Extract prefix and color from the first line
    first_line = lines[0]
    prefix = ""
    color_code = ""

    # Extract prefix if first line doesn't start with space
    if first_line and not first_line[0].isspace():
        prefix, color_code, _ = _extract_prefix_and_color(
            first_line, strip_ansi_escapes
        )

    # Process subsequent lines
    for line in lines[1:]:
        if not line.strip():  # Only process non-empty lines
            # Empty line
            result.append("")
            continue
        if not line[0].isspace():  # If line starts with whitespace, it's a continuation
            # This is a new log entry within the same message
            result.append(f"{timestamp}{line}")
            continue
        # Apply timestamp, color, prefix, and the continuation line
        result.append(
            _format_continuation_line(
                timestamp, prefix, line, color_code, strip_ansi_escapes
            )
        )

    return result
