import asyncio
from unittest.mock import MagicMock

import pytest

from aioesphomeapi._frame_helper import APINoiseFrameHelper, APIPlaintextFrameHelper
from aioesphomeapi.core import BadNameAPIError, InvalidEncryptionKeyAPIError
from aioesphomeapi.util import varuint_to_bytes

PREAMBLE = b"\x00"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "in_bytes, pkt_data, pkt_type",
    [
        (PREAMBLE + varuint_to_bytes(0) + varuint_to_bytes(1), b"", 1),
        (
            PREAMBLE + varuint_to_bytes(192) + varuint_to_bytes(1) + (b"\x42" * 192),
            (b"\x42" * 192),
            1,
        ),
        (
            PREAMBLE + varuint_to_bytes(192) + varuint_to_bytes(100) + (b"\x42" * 192),
            (b"\x42" * 192),
            100,
        ),
        (
            PREAMBLE + varuint_to_bytes(4) + varuint_to_bytes(100) + (b"\x42" * 4),
            (b"\x42" * 4),
            100,
        ),
        (
            PREAMBLE
            + varuint_to_bytes(8192)
            + varuint_to_bytes(8192)
            + (b"\x42" * 8192),
            (b"\x42" * 8192),
            8192,
        ),
        (
            PREAMBLE + varuint_to_bytes(256) + varuint_to_bytes(256) + (b"\x42" * 256),
            (b"\x42" * 256),
            256,
        ),
    ],
)
async def test_plaintext_frame_helper(in_bytes, pkt_data, pkt_type):
    for _ in range(5):
        packets = []

        def _packet(type_: int, data: bytes):
            packets.append((type_, data))

        def _on_error(exc: Exception):
            raise exc

        helper = APIPlaintextFrameHelper(on_pkt=_packet, on_error=_on_error)

        helper.data_received(in_bytes)

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == pkt_type
        assert data == pkt_data


@pytest.mark.asyncio
async def test_noise_frame_helper_incorrect_key():
    """Test that the noise frame helper raises InvalidEncryptionKeyAPIError on bad key."""
    outgoing_packets = [
        "010000",  # hello packet
        "010031001ed7f7bb0b74085418258ed5928931bc36ade7cf06937fcff089044d4ab142643f1b2c9935bb77696f23d930836737a4",
    ]
    incoming_packets = [
        "01000d01736572766963657465737400",
        "0100160148616e647368616b65204d4143206661696c757265",
    ]
    packets = []

    def _packet(type_: int, data: bytes):
        packets.append((type_, data))

    def _on_error(exc: Exception):
        raise exc

    helper = APINoiseFrameHelper(
        on_pkt=_packet,
        on_error=_on_error,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
    )
    helper._transport = MagicMock()

    for pkt in outgoing_packets:
        helper._write_frame(bytes.fromhex(pkt))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        for pkt in incoming_packets:
            helper.data_received(bytes.fromhex(pkt))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        await helper.perform_handshake()


@pytest.mark.asyncio
async def test_noise_incorrect_name():
    """Test we raise on bad name."""
    outgoing_packets = [
        "010000",  # hello packet
        "010031001ed7f7bb0b74085418258ed5928931bc36ade7cf06937fcff089044d4ab142643f1b2c9935bb77696f23d930836737a4",
    ]
    incoming_packets = [
        "01000d01736572766963657465737400",
        "0100160148616e647368616b65204d4143206661696c757265",
    ]
    packets = []

    def _packet(type_: int, data: bytes):
        packets.append((type_, data))

    def _on_error(exc: Exception):
        raise exc

    helper = APINoiseFrameHelper(
        on_pkt=_packet,
        on_error=_on_error,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="wrongname",
    )
    helper._transport = MagicMock()

    for pkt in outgoing_packets:
        helper._write_frame(bytes.fromhex(pkt))

    with pytest.raises(BadNameAPIError):
        for pkt in incoming_packets:
            helper.data_received(bytes.fromhex(pkt))

    with pytest.raises(BadNameAPIError):
        await helper.perform_handshake()
