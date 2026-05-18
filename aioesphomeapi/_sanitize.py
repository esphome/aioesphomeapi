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


def safe_label_str(raw: str, limit: int) -> str:
    """Strip non-printables and length-cap a peer-supplied label for log output."""
    return "".join(filter(str.isprintable, raw))[:limit]
