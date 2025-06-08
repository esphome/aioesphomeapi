"""Log parser for ESPHome log messages with ANSI color support."""

from __future__ import annotations

import re

# Pre-compiled regex for ANSI escape sequences
ANSI_ESCAPE = re.compile(
    r"(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])"
)

# ANSI reset sequences
ANSI_RESET_CODES = ("\033[0m", "\x1b[0m")
ANSI_RESET = "\033[0m"


def parse_log_message(
    text: str, timestamp: str, *, strip_ansi_escapes: bool = False
) -> list[str]:
    """Parse a log message and format it with timestamps and color preservation.

    Args:
        text: The log message text, potentially with ANSI codes and newlines
        timestamp: The timestamp string to prepend (e.g., "[08:00:00.000]")
        strip_ansi_escapes: If True, remove all ANSI escape sequences from output

    Returns:
        List of formatted lines ready to be printed
    """
    # Strip ANSI escapes if requested
    if strip_ansi_escapes:
        text = ANSI_ESCAPE.sub("", text)

    # Fast path for single line (most common case)
    if "\n" not in text:
        return [f"{timestamp}{text}"]

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
