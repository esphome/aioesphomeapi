from unittest.mock import MagicMock

import pytest

from aioesphomeapi._frame_helper import APINoiseFrameHelper, APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.base import WRITE_EXCEPTIONS
from aioesphomeapi._frame_helper.plain_text import _bytes_to_varuint as bytes_to_varuint
from aioesphomeapi._frame_helper.plain_text import (
    _cached_bytes_to_varuint as cached_bytes_to_varuint,
)
from aioesphomeapi._frame_helper.plain_text import (
    _cached_varuint_to_bytes as cached_varuint_to_bytes,
)
from aioesphomeapi._frame_helper.plain_text import _varuint_to_bytes as varuint_to_bytes
from aioesphomeapi.core import (
    BadNameAPIError,
    InvalidEncryptionKeyAPIError,
    SocketAPIError,
)

PREAMBLE = b"\x00"


class MockAPINoiseFrameHelper(APINoiseFrameHelper):
    def mock_write_frame(self, frame: bytes) -> None:
        """Write a packet to the socket.

        The entire packet must be written in a single call to write.
        """
        frame_len = len(frame)
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        try:
            self._writer(header + frame)
        except WRITE_EXCEPTIONS as err:
            raise SocketAPIError(
                f"{self._log_name}: Error while writing data: {err}"
            ) from err


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
async def test_plaintext_frame_helper(in_bytes, pkt_data, pkt_type):
    for _ in range(3):
        packets = []

        def _packet(type_: int, data: bytes):
            packets.append((type_, data))

        def _on_error(exc: Exception):
            raise exc

        helper = APIPlaintextFrameHelper(
            on_pkt=_packet, on_error=_on_error, client_info="my client", log_name="test"
        )

        helper.data_received(in_bytes)

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == pkt_type
        assert data == pkt_data

        # Make sure we correctly handle fragments
        for i in range(len(in_bytes)):
            helper.data_received(in_bytes[i : i + 1])

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

    helper = MockAPINoiseFrameHelper(
        on_pkt=_packet,
        on_error=_on_error,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
    )
    helper._transport = MagicMock()
    helper._writer = MagicMock()

    for pkt in outgoing_packets:
        helper.mock_write_frame(bytes.fromhex(pkt))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        for pkt in incoming_packets:
            helper.data_received(bytes.fromhex(pkt))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        await helper.perform_handshake(30)


@pytest.mark.asyncio
async def test_noise_frame_helper_incorrect_key_fragments():
    """Test that the noise frame helper raises InvalidEncryptionKeyAPIError on bad key with fragmented packets."""
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

    helper = MockAPINoiseFrameHelper(
        on_pkt=_packet,
        on_error=_on_error,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
    )
    helper._transport = MagicMock()
    helper._writer = MagicMock()

    for pkt in outgoing_packets:
        helper.mock_write_frame(bytes.fromhex(pkt))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        for pkt in incoming_packets:
            in_pkt = bytes.fromhex(pkt)
            for i in range(len(in_pkt)):
                helper.data_received(in_pkt[i : i + 1])

    with pytest.raises(InvalidEncryptionKeyAPIError):
        await helper.perform_handshake(30)


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

    helper = MockAPINoiseFrameHelper(
        on_pkt=_packet,
        on_error=_on_error,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="wrongname",
        client_info="my client",
        log_name="test",
    )
    helper._transport = MagicMock()
    helper._writer = MagicMock()

    for pkt in outgoing_packets:
        helper.mock_write_frame(bytes.fromhex(pkt))

    with pytest.raises(BadNameAPIError):
        for pkt in incoming_packets:
            helper.data_received(bytes.fromhex(pkt))

    with pytest.raises(BadNameAPIError):
        await helper.perform_handshake(30)


VARUINT_TESTCASES = [
    (0, b"\x00"),
    (42, b"\x2a"),
    (127, b"\x7f"),
    (128, b"\x80\x01"),
    (300, b"\xac\x02"),
    (65536, b"\x80\x80\x04"),
]


@pytest.mark.parametrize("val, encoded", VARUINT_TESTCASES)
def test_varuint_to_bytes(val, encoded):
    assert varuint_to_bytes(val) == encoded
    assert cached_varuint_to_bytes(val) == encoded


@pytest.mark.parametrize("val, encoded", VARUINT_TESTCASES)
def test_bytes_to_varuint(val, encoded):
    assert bytes_to_varuint(encoded) == val
    assert cached_bytes_to_varuint(encoded) == val
