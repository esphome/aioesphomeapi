import asyncio
from unittest.mock import MagicMock

import pytest

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper, APINoiseFrameHelper
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
async def test_noise_frame_helper_good_handshake():
    """Test that the noise frame helper can perform a handshake with the ESPHome device."""
    outgoing_packets = [
        "010000", # hello packet
        "010031006e6853c8afd676b53888df3b1ff0e0742c762888855c54b96a5b6e17366c53046ab29bd5f7bb59f48182ea190620a1fd"
    ]
    incoming_packets = [
        "01000d01736572766963657465737400",
        "01003100900d0da775dfe4744fe4498d32efc666b6ee30664b3047285d84f42a1f8bb16e574317a29f941a605a25b10a32615ac0"
    ]
    packets = []

    def _packet(type_: int, data: bytes):
        packets.append((type_, data))

    def _on_error(exc: Exception):
        raise exc

    helper = APINoiseFrameHelper(on_pkt=_packet, on_error=_on_error, noise_psk="OIwNWQp2NSwmf7BwfEywyAc9HMijdsef7Kate7b2K14=", expected_name="servicetest")
    helper._transport = MagicMock()

    for pkt in outgoing_packets:
        helper._write_frame(bytes.fromhex(pkt))

    for pkt in incoming_packets:    
        helper.data_received(bytes.fromhex(pkt))

    await helper.perform_handshake()


@pytest.mark.asyncio
async def test_noise_frame_helper_incorrect_key():
    """Test that the noise frame helper can perform a handshake with the ESPHome device."""
    outgoing_packets = [
        "010000", # hello packet
        "01003100be5444d8e188e893963fea601d94c0aa557a9a5ea628e6405beba115f17a312c07d03c2985bf476b55790ea7e74d617d"
    ]
    incoming_packets = [
        "0148616e647368616b65204d4143206661696c757265",
    ]
    packets = []

    def _packet(type_: int, data: bytes):
        packets.append((type_, data))

    def _on_error(exc: Exception):
        raise exc

    helper = APINoiseFrameHelper(on_pkt=_packet, on_error=_on_error, noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=", expected_name="servicetest")
    helper._transport = MagicMock()

    for pkt in outgoing_packets:
        helper._write_frame(bytes.fromhex(pkt))

    for pkt in incoming_packets:    
        helper.data_received(bytes.fromhex(pkt))

    import pprint
    pprint.pprint(['wait for handshake'])
    await helper.perform_handshake()
