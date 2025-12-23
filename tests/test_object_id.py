"""Tests for object_id computation module."""

from __future__ import annotations

import pytest

from aioesphomeapi.model import (
    BinarySensorInfo,
    DeviceInfo,
    SensorInfo,
    SubDeviceInfo,
    TextSensorInfo,
)
from aioesphomeapi.object_id import (
    compute_object_id,
    fill_missing_object_ids,
    sanitize,
    snake_case,
)

# Verification test: ensure computed object_id matches what ESPHome sends
# These are real examples of (name, object_id) pairs from ESPHome


@pytest.mark.parametrize(
    ("name", "expected_object_id"),
    [
        # Simple names
        ("temperature", "temperature"),
        ("Temperature", "temperature"),
        ("TEMPERATURE", "temperature"),
        # Names with spaces
        ("Temperature Sensor", "temperature_sensor"),
        ("My Friendly Device", "my_friendly_device"),
        ("Living Room Light", "living_room_light"),
        # Names with special characters
        ("Temperature (F)", "temperature__f_"),
        ("Sensor #1", "sensor__1"),
        ("CPU Usage %", "cpu_usage__"),
        ("Power [W]", "power__w_"),
        # Names with hyphens (preserved)
        ("test-device", "test-device"),
        ("my-sensor-name", "my-sensor-name"),
        # Names with underscores (preserved)
        ("test_device", "test_device"),
        ("my_sensor_name", "my_sensor_name"),
        # Mixed
        ("Test-Device_Name", "test-device_name"),
        ("Sensor 1 - Main", "sensor_1_-_main"),
        # Unicode (becomes underscores)
        ("Température", "temp_rature"),
        ("日本語", "___"),
        # Edge cases
        ("", ""),
        ("a", "a"),
        ("A", "a"),
        (" ", "_"),
        ("  ", "__"),
    ],
)
def test_compute_object_id_matches_esphome(name: str, expected_object_id: str) -> None:
    """Verify computed object_id matches what ESPHome would send.

    This test ensures that when ESPHome stops sending object_id,
    our client-side computation produces identical results.
    """
    assert compute_object_id(name) == expected_object_id


# snake_case tests


def test_snake_case_lowercase_passthrough() -> None:
    """Test that lowercase letters pass through unchanged."""
    assert snake_case("hello") == "hello"


def test_snake_case_uppercase_to_lowercase() -> None:
    """Test that uppercase letters are converted to lowercase."""
    assert snake_case("Hello") == "hello"
    assert snake_case("HELLO") == "hello"
    assert snake_case("HeLLo") == "hello"


def test_snake_case_space_to_underscore() -> None:
    """Test that spaces are converted to underscores."""
    assert snake_case("hello world") == "hello_world"
    assert snake_case("hello  world") == "hello__world"


def test_snake_case_mixed_case_and_spaces() -> None:
    """Test mixed case with spaces."""
    assert snake_case("Hello World") == "hello_world"
    assert snake_case("My Friendly Device") == "my_friendly_device"


def test_snake_case_special_chars_passthrough() -> None:
    """Test that special chars pass through (sanitize handles them)."""
    assert snake_case("hello-world") == "hello-world"
    assert snake_case("hello_world") == "hello_world"


def test_snake_case_empty_string() -> None:
    """Test empty string."""
    assert snake_case("") == ""


# sanitize tests


def test_sanitize_lowercase_passthrough() -> None:
    """Test that lowercase letters pass through unchanged."""
    assert sanitize("hello") == "hello"


def test_sanitize_digits_passthrough() -> None:
    """Test that digits pass through unchanged."""
    assert sanitize("hello123") == "hello123"
    assert sanitize("123") == "123"


def test_sanitize_underscore_passthrough() -> None:
    """Test that underscores pass through unchanged."""
    assert sanitize("hello_world") == "hello_world"


def test_sanitize_hyphen_passthrough() -> None:
    """Test that hyphens pass through unchanged."""
    assert sanitize("hello-world") == "hello-world"


def test_sanitize_uppercase_to_underscore() -> None:
    """Test that uppercase letters become underscores (not lowercase)."""
    # sanitize only keeps [a-z0-9_-], uppercase becomes underscore
    assert sanitize("Hello") == "_ello"
    assert sanitize("HELLO") == "_____"


def test_sanitize_special_chars_to_underscore() -> None:
    """Test that special characters become underscores."""
    assert sanitize("hello!") == "hello_"
    assert sanitize("hello@world") == "hello_world"
    assert sanitize("hello#$%^&*()world") == "hello________world"  # 8 special chars


def test_sanitize_unicode_to_underscore() -> None:
    """Test that unicode characters become underscores."""
    # This is why object_id is problematic for non-ASCII names
    assert sanitize("温度") == "__"
    assert sanitize("température") == "temp_rature"


def test_sanitize_empty_string() -> None:
    """Test empty string."""
    assert sanitize("") == ""


# compute_object_id tests (snake_case + sanitize)


def test_compute_object_id_simple_name() -> None:
    """Test simple lowercase name."""
    assert compute_object_id("temperature") == "temperature"


def test_compute_object_id_mixed_case() -> None:
    """Test mixed case name."""
    assert compute_object_id("Temperature") == "temperature"
    assert compute_object_id("TemperatureSensor") == "temperaturesensor"


def test_compute_object_id_spaces() -> None:
    """Test name with spaces."""
    assert compute_object_id("Temperature Sensor") == "temperature_sensor"
    assert compute_object_id("My Friendly Device") == "my_friendly_device"


def test_compute_object_id_special_chars() -> None:
    """Test name with special characters."""
    assert compute_object_id("Temperature (F)") == "temperature__f_"
    assert compute_object_id("Sensor #1") == "sensor__1"


def test_compute_object_id_hyphen_preserved() -> None:
    """Test that hyphens are preserved."""
    assert compute_object_id("test-device") == "test-device"
    assert compute_object_id("Test-Device") == "test-device"


def test_compute_object_id_underscore_preserved() -> None:
    """Test that underscores are preserved."""
    assert compute_object_id("test_device") == "test_device"


def test_compute_object_id_empty_string() -> None:
    """Test empty string."""
    assert compute_object_id("") == ""


# fill_missing_object_ids tests


def test_fill_missing_object_ids_named_entity_computes_from_name() -> None:
    """Test that named entities get object_id from entity name."""
    device_info = DeviceInfo(
        name="test-device",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="Temperature Sensor", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    assert len(result) == 1
    assert result[0].object_id == "temperature_sensor"
    assert result[0].name == "Temperature Sensor"  # Name unchanged


def test_fill_missing_object_ids_preserves_existing_object_id() -> None:
    """Test that existing object_id is not overwritten."""
    device_info = DeviceInfo(
        name="test-device",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="Temperature", object_id="custom_id")]

    result = fill_missing_object_ids(entities, device_info)

    assert len(result) == 1
    assert result[0].object_id == "custom_id"  # Preserved


def test_fill_missing_object_ids_empty_name_uses_device_name() -> None:
    """Test empty-name entity uses device name when no friendly_name or MAC suffix."""
    device_info = DeviceInfo(
        name="test-device",
        friendly_name="",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    assert len(result) == 1
    assert result[0].object_id == "test-device"


def test_fill_missing_object_ids_empty_name_uses_friendly_name() -> None:
    """Test empty-name entity uses friendly_name when set."""
    device_info = DeviceInfo(
        name="test-device",
        friendly_name="My Friendly Device",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    assert len(result) == 1
    assert result[0].object_id == "my_friendly_device"


def test_fill_missing_object_ids_empty_name_with_mac_suffix_uses_friendly_name() -> (
    None
):
    """Test empty-name entity with MAC suffix uses friendly_name."""
    # Device name ends with MAC suffix (last 6 hex chars)
    device_info = DeviceInfo(
        name="test-device-ddeeff",
        friendly_name="My Device",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    assert len(result) == 1
    assert result[0].object_id == "my_device"


def test_fill_missing_object_ids_mac_suffix_no_friendly_name_is_empty() -> None:
    """Test bug-for-bug compat: MAC suffix + no friendly_name = empty object_id."""
    # This is the edge case where MAC suffix is enabled but friendly_name is empty
    device_info = DeviceInfo(
        name="test-device-ddeeff",
        friendly_name="",  # Empty friendly_name
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    assert len(result) == 1
    # Bug-for-bug compatibility: empty object_id
    assert result[0].object_id == ""


def test_fill_missing_object_ids_empty_name_on_sub_device() -> None:
    """Test empty-name entity on sub-device uses sub-device name."""
    device_info = DeviceInfo(
        name="main-device",
        friendly_name="Main Device",
        mac_address="AA:BB:CC:DD:EE:FF",
        devices=[
            SubDeviceInfo(device_id=1, name="Sub Device One"),
            SubDeviceInfo(device_id=2, name="Sub Device Two"),
        ],
    )
    entities: list[SensorInfo] = [
        SensorInfo(name="", device_id=1, object_id=""),
        SensorInfo(name="", device_id=2, object_id=""),
    ]

    result = fill_missing_object_ids(entities, device_info)

    assert len(result) == 2
    assert result[0].object_id == "sub_device_one"
    assert result[1].object_id == "sub_device_two"


def test_fill_missing_object_ids_mixed_entities() -> None:
    """Test mix of named entities, empty-name on main, and empty-name on sub-devices."""
    device_info = DeviceInfo(
        name="test-device",
        friendly_name="Test Device",
        mac_address="AA:BB:CC:DD:EE:FF",
        devices=[
            SubDeviceInfo(device_id=1, name="Sub One"),
        ],
    )
    entities: list[SensorInfo | BinarySensorInfo | TextSensorInfo] = [
        SensorInfo(name="Temperature", object_id=""),  # Named
        BinarySensorInfo(name="", object_id=""),  # Empty name, main device
        TextSensorInfo(name="", device_id=1, object_id=""),  # Empty name, sub-device
        SensorInfo(name="Humidity", object_id="existing"),  # Has object_id
    ]

    result = fill_missing_object_ids(entities, device_info)

    assert len(result) == 4
    assert result[0].object_id == "temperature"  # From entity name
    assert result[1].object_id == "test_device"  # From friendly_name
    assert result[2].object_id == "sub_one"  # From sub-device name
    assert result[3].object_id == "existing"  # Preserved


def test_fill_missing_object_ids_immutability() -> None:
    """Test that original entities are not modified."""
    device_info = DeviceInfo(
        name="test-device",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    original = SensorInfo(name="Temperature", object_id="")
    entities: list[SensorInfo] = [original]

    result = fill_missing_object_ids(entities, device_info)

    # Original should be unchanged
    assert original.object_id == ""
    # Result should be new object
    assert result[0].object_id == "temperature"
    assert result[0] is not original


def test_fill_missing_object_ids_empty_list() -> None:
    """Test empty entities list."""
    device_info = DeviceInfo(
        name="test-device",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = []

    result = fill_missing_object_ids(entities, device_info)

    assert result == []


# MAC suffix inference tests


def test_mac_suffix_detected() -> None:
    """Test that MAC suffix is detected in device name."""
    # MAC address AA:BB:CC:DD:EE:FF -> suffix "ddeeff"
    device_info = DeviceInfo(
        name="device-ddeeff",
        friendly_name="",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    # With MAC suffix detected and empty friendly_name, object_id is empty
    assert result[0].object_id == ""


def test_mac_suffix_requires_hyphen_prefix() -> None:
    """Test that MAC suffix must have hyphen prefix."""
    device_info = DeviceInfo(
        name="deviceddeeff",  # No hyphen before suffix
        friendly_name="",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    # No MAC suffix detected, falls back to device name
    assert result[0].object_id == "deviceddeeff"


def test_mac_suffix_case_sensitive_in_device_name() -> None:
    """Test that MAC suffix check is case-sensitive for device name.

    The MAC suffix is extracted as lowercase from mac_address, so device
    names with uppercase suffix won't match and will fall back to using
    the device name directly.
    """
    device_info = DeviceInfo(
        name="device-DDEEFF",  # Uppercase suffix - won't match lowercase check
        friendly_name="",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    # MAC suffix NOT detected (case-sensitive), falls back to device name
    # compute_object_id("device-DDEEFF") -> snake_case -> "device-ddeeff"
    assert result[0].object_id == "device-ddeeff"


def test_mac_suffix_partial_not_detected() -> None:
    """Test that partial MAC suffix is not detected."""
    device_info = DeviceInfo(
        name="device-eeff",  # Only 4 chars, not 6
        friendly_name="",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    # Partial suffix not detected, falls back to device name
    assert result[0].object_id == "device-eeff"


def test_mac_suffix_empty_mac_address() -> None:
    """Test that empty MAC address doesn't cause false positive."""
    device_info = DeviceInfo(
        name="device-",  # Ends with hyphen, could false-match empty suffix
        friendly_name="",
        mac_address="",  # Empty MAC
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    # Empty MAC should not match, falls back to device name
    assert result[0].object_id == "device-"


def test_mac_suffix_short_mac_address() -> None:
    """Test that short MAC address doesn't cause issues."""
    device_info = DeviceInfo(
        name="device-abc",  # Ends with hyphen + 3 chars
        friendly_name="",
        mac_address="AB:CD",  # Only 4 hex chars
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    # Short MAC should not match, falls back to device name
    assert result[0].object_id == "device-abc"


def test_mac_suffix_malformed_mac_address() -> None:
    """Test that malformed MAC address is handled safely."""
    device_info = DeviceInfo(
        name="device-12345",
        friendly_name="",
        mac_address="not-a-mac",  # Malformed
    )
    entities: list[SensorInfo] = [SensorInfo(name="", object_id="")]

    result = fill_missing_object_ids(entities, device_info)

    # Malformed MAC should not cause issues, falls back to device name
    assert result[0].object_id == "device-12345"
