from __future__ import annotations

from aioesphomeapi.model_conversions import (
    STATE_TYPE_TO_INFO_TYPE,
    SUBSCRIBE_STATES_RESPONSE_TYPES,
)


def test_state_type_to_info_type_covers_all_state_types() -> None:
    """Every state type the client decodes must have an info type mapping,
    otherwise log_runner falls back to info=None and formatting degrades.
    """
    state_types = set(SUBSCRIBE_STATES_RESPONSE_TYPES.values())
    missing = state_types - STATE_TYPE_TO_INFO_TYPE.keys()
    assert not missing, f"STATE_TYPE_TO_INFO_TYPE is missing: {missing}"
