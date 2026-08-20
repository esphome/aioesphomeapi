from __future__ import annotations

import base64

import pytest

from aioesphomeapi.core import (
    MESSAGE_NUMBER_TO_PROTO,
    MESSAGE_TYPE_TO_PROTO,
    ZERO_NOISE_PSK,
    wifi_mac_to_bluetooth_mac,
)


def test_zero_noise_psk_is_all_zero_bytes():
    """Test that ZERO_NOISE_PSK decodes to exactly 32 zero bytes."""
    assert base64.b64decode(ZERO_NOISE_PSK) == bytes(32)


# Message ids that were removed before ever shipping; they are never reused.
RETIRED_MESSAGE_TYPES = {128, 149}


def test_order_and_no_missing_numbers_in_message_type_to_proto():
    """Test that MESSAGE_TYPE_TO_PROTO is ordered and only skips retired numbers."""
    numbers = list(MESSAGE_TYPE_TO_PROTO)
    assert numbers == sorted(numbers)
    assert set(numbers) == set(range(1, numbers[-1] + 1)) - RETIRED_MESSAGE_TYPES


def test_message_number_to_proto_is_indexed_by_message_type():
    """Test MESSAGE_NUMBER_TO_PROTO index equals message type - 1, retired ids None."""
    for number, klass in MESSAGE_TYPE_TO_PROTO.items():
        assert MESSAGE_NUMBER_TO_PROTO[number - 1] is klass
    for number in RETIRED_MESSAGE_TYPES:
        assert MESSAGE_NUMBER_TO_PROTO[number - 1] is None


def test_wifi_mac_to_bluetooth_mac():
    """Test converting WiFi MAC address to Bluetooth MAC address."""
    # Test with uppercase MAC without colons
    assert wifi_mac_to_bluetooth_mac("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:01"

    # Test with lowercase MAC with colons
    assert wifi_mac_to_bluetooth_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:01"

    # Test with uppercase MAC with colons
    assert wifi_mac_to_bluetooth_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:01"

    # Test with mixed case
    assert wifi_mac_to_bluetooth_mac("Aa:Bb:Cc:Dd:Ee:Ff") == "AA:BB:CC:DD:EE:01"

    # Test rollover (FE + 2 = 00, wraps around)
    assert wifi_mac_to_bluetooth_mac("AA:BB:CC:DD:EE:FE") == "AA:BB:CC:DD:EE:00"

    # Test edge case with FF (FF + 2 = 01, wraps around)
    assert wifi_mac_to_bluetooth_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:01"

    # Test with 00
    assert wifi_mac_to_bluetooth_mac("AA:BB:CC:DD:EE:00") == "AA:BB:CC:DD:EE:02"

    # Test with FD (FD + 2 = FF)
    assert wifi_mac_to_bluetooth_mac("AA:BB:CC:DD:EE:FD") == "AA:BB:CC:DD:EE:FF"


def test_wifi_mac_to_bluetooth_mac_invalid():
    """Test wifi_mac_to_bluetooth_mac with invalid inputs."""
    # Test with invalid length
    with pytest.raises(ValueError, match="Invalid MAC address format"):
        wifi_mac_to_bluetooth_mac("AA:BB:CC:DD:EE")

    # Test with invalid characters
    with pytest.raises(ValueError, match="Invalid MAC address format"):
        wifi_mac_to_bluetooth_mac("GG:BB:CC:DD:EE:FF")

    # Test with completely invalid input
    with pytest.raises(ValueError, match="Invalid MAC address format"):
        wifi_mac_to_bluetooth_mac("not a mac address")
