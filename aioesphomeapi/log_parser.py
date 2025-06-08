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


def parse_log_message(text: str, timestamp: str) -> list[str]:
    """Parse a log message and format it with timestamps and color preservation.

    Args:
        text: The log message text, potentially with ANSI codes and newlines
        timestamp: The timestamp string to prepend (e.g., "[08:00:00.000]")

    Returns:
        List of formatted lines ready to be printed
    """
    # Fast path for single line (most common case)
    if "\n" not in text:
        return [f"{timestamp}{text}"]

    # Multi-line handling
    lines = text.split("\n")

    # Remove trailing empty line if present (common when messages end with \n)
    if lines and lines[-1] == "":
        lines.pop()

    # Also remove if last line is just ANSI reset codes
    if lines and lines[-1] in ANSI_RESET_CODES:
        lines.pop()
    result: list[str] = []

    # Process the first line
    result.append(f"{timestamp}{lines[0]}")

    # Extract prefix and color from the first line
    first_line = lines[0]
    prefix = ""
    color_code = ""

    # Extract ANSI color code at the beginning if present
    color_match = ANSI_ESCAPE.match(first_line)
    if color_match:
        color_code = color_match.group(0)
        # Remove color code from line for prefix extraction
        first_line_no_color = first_line[len(color_code) :]
    else:
        first_line_no_color = first_line

    # Find the last ']:' which marks the end of the ESPHome prefix
    # Look for pattern like [C][template.sensor:022]:
    last_bracket_colon = first_line_no_color.rfind(
        "]:", 0, len(first_line_no_color) // 2
    )
    if last_bracket_colon != -1:
        prefix = first_line_no_color[: last_bracket_colon + 2]  # Include the ']:' part

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
        if prefix:
            if color_code:
                # Add reset at end to ensure color doesn't bleed
                # But only if the line doesn't already end with a reset
                if line.endswith(ANSI_RESET_CODES):
                    result.append(f"{timestamp}{color_code}{prefix} {line}")
                else:
                    result.append(f"{timestamp}{color_code}{prefix} {line}{ANSI_RESET}")
            else:
                result.append(f"{timestamp}{prefix} {line}")
        # No prefix found, just add timestamp and line
        elif color_code:
            if line.endswith(ANSI_RESET_CODES):
                result.append(f"{timestamp}{color_code}{line}")
            else:
                result.append(f"{timestamp}{color_code}{line}{ANSI_RESET}")
        else:
            result.append(f"{timestamp}{line}")

    return result
