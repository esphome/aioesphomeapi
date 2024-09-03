from __future__ import annotations

from aioesphomeapi.core import MESSAGE_TYPE_TO_PROTO


def test_order_and_no_missing_numbers_in_message_type_to_proto():
    """Test that MESSAGE_TYPE_TO_PROTO has no missing numbers."""
    for idx, (k, v) in enumerate(MESSAGE_TYPE_TO_PROTO.items()):
        assert idx + 1 == k
