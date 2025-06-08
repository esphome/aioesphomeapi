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
                # Extract ANSI color code at the beginning if present
                line_no_color = line
                if not self.strip_ansi_escapes and (
                    color_match := ANSI_ESCAPE.match(line)
                ):
                    self._current_color_code = color_match.group(0)
                    line_no_color = line[len(self._current_color_code) :]

                # Find the ESPHome prefix
                bracket_colon = line_no_color.find("]:")
                if bracket_colon != -1:
                    self._current_prefix = line_no_color[: bracket_colon + 2]

            # Format the first line
            output = f"{timestamp}{line}"

            # Add reset if line has color but no reset at end
            if (
                not self.strip_ansi_escapes
                and line
                and not line.endswith(ANSI_RESET_CODES)
                and ("\033[" in line or "\x1b[" in line)
            ):
                output += ANSI_RESET

            return output
        else:
            # This is a continuation line
            if not line.strip():
                return ""

            # Apply prefix to continuation
            line_content = (
                f"{self._current_prefix} {line}" if self._current_prefix else line
            )

            if self._current_color_code and not self.strip_ansi_escapes:
                # Add color and reset
                reset = "" if line.endswith(ANSI_RESET_CODES) else ANSI_RESET
                return f"{timestamp}{self._current_color_code}{line_content}{reset}"
            else:
                return f"{timestamp}{line_content}"


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
    # Check if line contains ANSI codes - using direct string search for efficiency
    if (
        not strip_ansi_escapes
        and lines[0]
        and not lines[0].endswith(ANSI_RESET_CODES)
        and ("\033[" in lines[0] or "\x1b[" in lines[0])
    ):
        first_line_output += ANSI_RESET

    result.append(first_line_output)

    # Extract prefix and color from the first line
    first_line = lines[0]
    prefix = ""
    color_code = ""

    # Extract prefix if first line doesn't start with space
    if first_line and not first_line[0].isspace():
        # Extract ANSI color code at the beginning if present (only if not stripping)
        first_line_no_color = first_line
        if not strip_ansi_escapes and (color_match := ANSI_ESCAPE.match(first_line)):
            color_code = color_match.group(0)
            # Remove color code from line for prefix extraction
            first_line_no_color = first_line[len(color_code) :]

        # Find the ESPHome prefix - the first ']:' is always the split point
        # ESPHome log format: [LEVEL][component:line]: message
        # The first ']:' will always be at the end of the component:line part
        bracket_colon = first_line_no_color.find("]:")
        if bracket_colon != -1:
            prefix = first_line_no_color[: bracket_colon + 2]

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
        # Build the line components
        line_content = f"{prefix} {line}" if prefix else line

        if color_code and not strip_ansi_escapes:
            # Add reset at end to ensure color doesn't bleed
            # But only if the line doesn't already end with a reset
            reset = "" if line.endswith(ANSI_RESET_CODES) else ANSI_RESET
            result.append(f"{timestamp}{color_code}{line_content}{reset}")
        else:
            result.append(f"{timestamp}{line_content}")

    return result
