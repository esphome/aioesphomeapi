from __future__ import annotations

import sys

import pytest

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.plain_text import _varuint_to_bytes as varuint_to_bytes

from .common import mock_data_received
from .conftest import make_mock_connection

PREAMBLE = b"\x00"

NOISE_HELLO = b"\x01\x00\x00"


def test_skip_win32():
    if sys.platform == "win32":
        pytest.skip("Skip on Windows", allow_module_level=True)
    assert True


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
        (
            PREAMBLE + varuint_to_bytes(1) + varuint_to_bytes(32768) + b"\x42",
            b"\x42",
            32768,
        ),
        (
            PREAMBLE
            + varuint_to_bytes(32768)
            + varuint_to_bytes(32768)
            + (b"\x42" * 32768),
            (b"\x42" * 32768),
            32768,
        ),
    ],
)
@pytest.mark.asyncio
async def test_plaintext_frame_helper(
    in_bytes: bytes, pkt_data: bytes, pkt_type: int
) -> None:
    for _ in range(3):
        connection, packets = make_mock_connection()
        helper = APIPlaintextFrameHelper(
            connection=connection, client_info="my client", log_name="test"
        )

        mock_data_received(helper, in_bytes)

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == pkt_type
        assert data == pkt_data

        # Make sure we correctly handle fragments
        for i in range(len(in_bytes)):
            mock_data_received(helper, in_bytes[i : i + 1])

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == pkt_type
        assert data == pkt_data
        helper.close()
