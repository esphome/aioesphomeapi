"""Utilities for computing entity object_id from API data.

When object_id is empty in the API response, it can be computed client-side
using the algorithm in this module.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from .model import DeviceInfo, EntityInfo

_EntityInfoT = TypeVar("_EntityInfoT", bound="EntityInfo")


def _to_snake_case_char(c: str) -> str:
    """Convert a single character to snake_case equivalent."""
    if c == " ":
        return "_"
    if "A" <= c <= "Z":
        return c.lower()
    return c


def _to_sanitized_char(c: str) -> str:
    """Convert a single character to sanitized equivalent."""
    # Keep lowercase letters, digits, underscore, and hyphen
    if "a" <= c <= "z" or "0" <= c <= "9" or c in "_-":
        return c
    return "_"


def snake_case(name: str) -> str:
    """Convert a name to snake_case."""
    return "".join(_to_snake_case_char(c) for c in name)


def sanitize(name: str) -> str:
    """Sanitize a name to only contain [a-z0-9_-]."""
    return "".join(_to_sanitized_char(c) for c in name)


def compute_object_id(name: str) -> str:
    """Compute object_id from a name using snake_case + sanitize."""
    return sanitize(snake_case(name))


def _infer_name_add_mac_suffix(device_info: DeviceInfo) -> bool:
    """Infer name_add_mac_suffix from device name ending with MAC suffix."""
    # Guard against missing or malformed MAC addresses
    cleaned_mac = device_info.mac_address.replace(":", "")
    if len(cleaned_mac) < 6:
        return False
    mac_suffix = cleaned_mac[-6:].lower()
    return device_info.name.endswith(f"-{mac_suffix}")


def _get_name_for_object_id(
    entity: EntityInfo,
    device_info: DeviceInfo,
    device_id_to_name: dict[int, str],
) -> str:
    """Get the name used for object_id computation.

    Args:
        entity: The entity to get name for
        device_info: Device info from the API
        device_id_to_name: Mapping of device_id to device name for sub-devices

    Returns:
        The name to use for object_id computation
    """
    if entity.name:
        return entity.name
    if entity.device_id != 0:
        return device_id_to_name[entity.device_id]
    # If friendly_name is set, always use it
    if device_info.friendly_name:
        return device_info.friendly_name
    # Only compute MAC suffix when friendly_name is empty
    if _infer_name_add_mac_suffix(device_info):
        return ""  # Bug-for-bug compat: MAC suffix + no friendly_name = empty
    return device_info.name


def compute_entity_object_id(
    entity: EntityInfo,
    device_info: DeviceInfo,
    device_id_to_name: dict[int, str],
) -> str:
    """Compute object_id for an entity.

    Args:
        entity: The entity to compute object_id for
        device_info: Device info from the API
        device_id_to_name: Mapping of device_id to device name for sub-devices

    Returns:
        The computed object_id string
    """
    name_for_id = _get_name_for_object_id(entity, device_info, device_id_to_name)
    return compute_object_id(name_for_id)


def fill_missing_object_ids(
    entities: list[_EntityInfoT],
    device_info: DeviceInfo,
) -> list[_EntityInfoT]:
    """Fill in missing object_id values for entities.

    When object_id is empty in the API response, this function computes it
    using the same algorithm as ESPHome.

    Args:
        entities: List of entities to process
        device_info: Device info from the API

    Returns:
        A new list of entities with object_id filled in where missing
    """
    # Build device_id -> name lookup from sub-devices
    device_id_to_name = {d.device_id: d.name for d in device_info.devices}

    result: list[_EntityInfoT] = []
    for entity in entities:
        if not entity.object_id:
            # Compute object_id and create new entity with it filled in
            object_id = compute_entity_object_id(entity, device_info, device_id_to_name)
            # All EntityInfo subclasses are frozen dataclasses
            entity = replace(entity, object_id=object_id)  # type: ignore[type-var]
        result.append(entity)
    return result
