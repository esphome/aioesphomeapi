from __future__ import annotations

from aioesphomeapi.model import CameraInfo, CameraState
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


def test_state_type_to_info_type_includes_camera_state() -> None:
    """CameraState is produced from CameraImageResponse rather than a
    subscribe-state response, so it is not picked up by the auto-built
    mapping and must be added explicitly. Without this entry, log_runner
    warns on every camera frame.
    """
    assert STATE_TYPE_TO_INFO_TYPE[CameraState] is CameraInfo
