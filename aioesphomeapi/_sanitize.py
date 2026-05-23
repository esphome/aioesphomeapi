"""Sanitize peer-supplied labels before logging or printing them.

Shared by the noise hello / handshake-reject paths and the discover CLI;
strips non-printable characters and length-caps the result so a hostile
remote can't inject ANSI escapes, newlines or oversized values into the
operator's terminal or logs.
"""

from __future__ import annotations

# Caps match the firmware's actual wire-format limits:
#   - name: ESPHOME_DEVICE_NAME_MAX_LEN = 31 (validate_hostname in core/config.py)
#   - mac: MAC_ADDRESS_BUFFER_SIZE - 1 = 12 (lowercase hex, no separator)
#   - explanation: 32-byte handshake-reject buffer minus the 1-byte failure code
# A small extra margin on each lets benign forward-compat tweaks (e.g. firmware
# bumping the max name length by a few chars) through without breaking clients.
MAX_NAME_LEN = 32
MAX_MAC_LEN = 16
MAX_EXPLANATION_LEN = 64

__all__ = (
    "MAX_EXPLANATION_LEN",
    "MAX_MAC_LEN",
    "MAX_NAME_LEN",
    "safe_label_str",
)


# Alias so the `limit` annotation below isn't interpreted as a C-int type
# declaration by Cython — the .pxd already declares `int limit` and a bare
# `int` annotation would clash with it ("Function signature does not match
# previous declaration"). Mirrors the same workaround in _frame_helper/base.py.
_int = int


def safe_label_str(raw: str, limit: _int) -> str:
    """Strip non-printables and length-cap a peer-supplied label for log output."""
    return "".join(filter(str.isprintable, raw))[:limit]
