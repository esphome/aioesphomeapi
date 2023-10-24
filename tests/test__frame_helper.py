from __future__ import annotations

import asyncio
import base64
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from noise.connection import NoiseConnection  # type: ignore[import-untyped]

from aioesphomeapi._frame_helper import APINoiseFrameHelper, APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.base import WRITE_EXCEPTIONS
from aioesphomeapi._frame_helper.noise import ESPHOME_NOISE_BACKEND, NOISE_HELLO
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
    HandshakeAPIError,
    InvalidEncryptionKeyAPIError,
    SocketAPIError,
)

from .common import async_fire_time_changed, utcnow

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


@pytest.mark.asyncio
async def test_noise_timeout():
    """Test we raise on bad name."""
    outgoing_packets = [
        "010000",  # hello packet
        "010031001ed7f7bb0b74085418258ed5928931bc36ade7cf06937fcff089044d4ab142643f1b2c9935bb77696f23d930836737a4",
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

    task = asyncio.create_task(helper.perform_handshake(30))
    await asyncio.sleep(0)
    async_fire_time_changed(utcnow() + timedelta(seconds=60))
    await asyncio.sleep(0)
    with pytest.raises(HandshakeAPIError):
        await task


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


@pytest.mark.asyncio
async def test_noise_frame_helper_handshake_failure():
    """Test the noise frame helper handshake failure."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    packets = []
    writes = []

    def _packet(type_: int, data: bytes):
        packets.append((type_, data))

    def _writer(data: bytes):
        writes.append(data)

    def _on_error(exc: Exception):
        raise exc

    helper = MockAPINoiseFrameHelper(
        on_pkt=_packet,
        on_error=_on_error,
        noise_psk=noise_psk,
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
    )
    helper._transport = MagicMock()
    helper._writer = _writer

    proto = NoiseConnection.from_name(
        b"Noise_NNpsk0_25519_ChaChaPoly_SHA256", backend=ESPHOME_NOISE_BACKEND
    )
    proto.set_as_responder()
    proto.set_psks(psk_bytes)
    proto.set_prologue(b"NoiseAPIInit\x00\x00")
    proto.start_handshake()

    handshake_task = asyncio.create_task(helper.perform_handshake(30))
    await asyncio.sleep(0)  # let the task run to read the hello packet

    assert len(writes) == 1
    handshake_pkt = writes.pop()

    noise_hello = handshake_pkt[0:3]
    pkt_header = handshake_pkt[3:6]
    assert noise_hello == NOISE_HELLO
    assert pkt_header[0] == 1  # type
    pkg_length_high = pkt_header[1]
    pkg_length_low = pkt_header[2]
    pkg_length = (pkg_length_high << 8) + pkg_length_low
    assert pkg_length == 49
    noise_prefix = handshake_pkt[6:7]
    assert noise_prefix == b"\x00"
    encrypted_payload = handshake_pkt[7:]

    decrypted = proto.read_message(encrypted_payload)
    assert decrypted == b""

    hello_pkt = b"\x01servicetest\0"
    preamble = 1
    hello_pkg_length = len(hello_pkt)
    hello_pkg_length_high = (hello_pkg_length >> 8) & 0xFF
    hello_pkg_length_low = hello_pkg_length & 0xFF
    hello_header = bytes((preamble, hello_pkg_length_high, hello_pkg_length_low))
    hello_pkt_with_header = hello_header + hello_pkt
    helper.data_received(hello_pkt_with_header)

    error_pkt = b"\x01forced to fail"
    preamble = 1
    error_pkg_length = len(error_pkt)
    error_pkg_length_high = (error_pkg_length >> 8) & 0xFF
    error_pkg_length_low = error_pkg_length & 0xFF
    error_header = bytes((preamble, error_pkg_length_high, error_pkg_length_low))
    error_pkt_with_header = error_header + error_pkt

    with pytest.raises(HandshakeAPIError, match="forced to fail"):
        helper.data_received(error_pkt_with_header)

    with pytest.raises(HandshakeAPIError, match="forced to fail"):
        await handshake_task


@pytest.mark.asyncio
async def test_noise_frame_helper_handshake_success_with_single_packet():
    """Test the noise frame helper handshake success with a single packet."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    packets = []
    writes = []

    def _packet(type_: int, data: bytes):
        packets.append((type_, data))

    def _writer(data: bytes):
        writes.append(data)

    def _on_error(exc: Exception):
        raise exc

    helper = MockAPINoiseFrameHelper(
        on_pkt=_packet,
        on_error=_on_error,
        noise_psk=noise_psk,
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
    )
    helper._transport = MagicMock()
    helper._writer = _writer

    proto = NoiseConnection.from_name(
        b"Noise_NNpsk0_25519_ChaChaPoly_SHA256", backend=ESPHOME_NOISE_BACKEND
    )
    proto.set_as_responder()
    proto.set_psks(psk_bytes)
    proto.set_prologue(b"NoiseAPIInit\x00\x00")
    proto.start_handshake()

    handshake_task = asyncio.create_task(helper.perform_handshake(30))
    await asyncio.sleep(0)  # let the task run to read the hello packet

    assert len(writes) == 1
    handshake_pkt = writes.pop()

    noise_hello = handshake_pkt[0:3]
    pkt_header = handshake_pkt[3:6]
    assert noise_hello == NOISE_HELLO
    assert pkt_header[0] == 1  # type
    pkg_length_high = pkt_header[1]
    pkg_length_low = pkt_header[2]
    pkg_length = (pkg_length_high << 8) + pkg_length_low
    assert pkg_length == 49
    noise_prefix = handshake_pkt[6:7]
    assert noise_prefix == b"\x00"
    encrypted_payload = handshake_pkt[7:]

    decrypted = proto.read_message(encrypted_payload)
    assert decrypted == b""

    hello_pkt = b"\x01servicetest\0"
    preamble = 1
    hello_pkg_length = len(hello_pkt)
    hello_pkg_length_high = (hello_pkg_length >> 8) & 0xFF
    hello_pkg_length_low = hello_pkg_length & 0xFF
    hello_header = bytes((preamble, hello_pkg_length_high, hello_pkg_length_low))
    hello_pkt_with_header = hello_header + hello_pkt
    helper.data_received(hello_pkt_with_header)

    handshake = proto.write_message(b"")
    handshake_pkt = b"\x00" + handshake
    preamble = 1
    handshake_pkg_length = len(handshake_pkt)
    handshake_pkg_length_high = (handshake_pkg_length >> 8) & 0xFF
    handshake_pkg_length_low = handshake_pkg_length & 0xFF
    handshake_header = bytes(
        (preamble, handshake_pkg_length_high, handshake_pkg_length_low)
    )
    handshake_with_header = handshake_header + handshake_pkt

    helper.data_received(handshake_with_header)

    assert not writes

    await handshake_task
    helper.write_packet(1, b"to device")
    encrypted_packet = writes.pop()
    header = encrypted_packet[0:1]
    assert header == b"\x01"
    pkg_length_high = encrypted_packet[1]
    pkg_length_low = encrypted_packet[2]
    pkg_length = (pkg_length_high << 8) + pkg_length_low
    assert len(encrypted_packet) == 3 + pkg_length

    msg_type = 42
    msg_type_high = (msg_type >> 8) & 0xFF
    msg_type_low = msg_type & 0xFF
    msg_length = len(encrypted_payload)
    msg_length_high = (msg_length >> 8) & 0xFF
    msg_length_low = msg_length & 0xFF
    msg_header = bytes((msg_type_high, msg_type_low, msg_length_high, msg_length_low))
    encrypted_payload = proto.encrypt(msg_header + b"from device")

    preamble = 1
    encrypted_pkg_length = len(encrypted_payload)
    encrypted_pkg_length_high = (encrypted_pkg_length >> 8) & 0xFF
    encrypted_pkg_length_low = encrypted_pkg_length & 0xFF
    encrypted_header = bytes(
        (preamble, encrypted_pkg_length_high, encrypted_pkg_length_low)
    )
    helper.data_received(encrypted_header + encrypted_payload)

    assert packets == [(42, b"from device")]
    helper.close()
