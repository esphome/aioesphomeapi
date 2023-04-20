import asyncio
from unittest.mock import MagicMock

import pytest

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
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
