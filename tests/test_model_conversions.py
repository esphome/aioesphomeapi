from __future__ import annotations

from aioesphomeapi.model import CameraInfo, CameraState, EntityInfo, EntityState
from aioesphomeapi.model_conversions import (
    LIST_ENTITIES_SERVICES_RESPONSE_TYPES,
    STATE_TYPE_TO_INFO_TYPE,
    SUBSCRIBE_STATES_RESPONSE_TYPES,
)


def _model_subclass_names(cls: type) -> set[str]:
    # Compare by name, not identity: @dataclass(slots=True) leaves the
    # pre-slots intermediate class registered in __subclasses__() too, so
    # identity comparison double-counts every model class. Restrict to the
    # model module so ad-hoc test doubles or downstream consumer subclasses
    # don't pollute the set.
    module = cls.__module__
    names: set[str] = set()
    for sub in cls.__subclasses__():
        if sub.__module__ == module:
            names.add(sub.__name__)
        names |= _model_subclass_names(sub)
    return names


def test_subscribe_states_response_types_covers_all_state_types() -> None:
    """Pin proto->state decoding coverage for every EntityState subclass.

    A new state type defined in model.py but not wired into
    SUBSCRIBE_STATES_RESPONSE_TYPES is silently undecodable. CameraState is
    the lone exception — it is produced from CameraImageResponse.
    """
    decoded = {state.__name__ for state in SUBSCRIBE_STATES_RESPONSE_TYPES.values()}
    missing = _model_subclass_names(EntityState) - decoded - {"CameraState"}
    assert not missing, f"SUBSCRIBE_STATES_RESPONSE_TYPES is missing: {missing}"


def test_list_entities_response_types_covers_all_info_types() -> None:
    """Pin proto->info decoding coverage for every EntityInfo subclass.

    A new info type defined in model.py but not wired into
    LIST_ENTITIES_SERVICES_RESPONSE_TYPES is silently unrecognized when the
    device lists its entities.
    """
    listed = {
        info.__name__
        for info in LIST_ENTITIES_SERVICES_RESPONSE_TYPES.values()
        if info is not None
    }
    missing = _model_subclass_names(EntityInfo) - listed
    assert not missing, f"LIST_ENTITIES_SERVICES_RESPONSE_TYPES is missing: {missing}"


def test_state_type_to_info_type_covers_all_state_types() -> None:
    """Pin info-type mapping coverage for every decoded state type.

    Every state type the client decodes must have an info type mapping,
    otherwise log_runner falls back to info=None and formatting degrades.
    """
    state_types = set(SUBSCRIBE_STATES_RESPONSE_TYPES.values())
    missing = state_types - STATE_TYPE_TO_INFO_TYPE.keys()
    assert not missing, f"STATE_TYPE_TO_INFO_TYPE is missing: {missing}"


def test_state_type_to_info_type_includes_camera_state() -> None:
    """Pin the explicit CameraState mapping for log_runner.

    CameraState is produced from CameraImageResponse rather than a
    subscribe-state response, so it is not picked up by the auto-built
    mapping and must be added explicitly. Without this entry, log_runner
    warns on every camera frame.
    """
    assert STATE_TYPE_TO_INFO_TYPE[CameraState] is CameraInfo
