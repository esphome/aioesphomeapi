from __future__ import annotations

import asyncio
import base64
from collections.abc import Iterable
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aioesphomeapi import APIConnection, EncryptionPlaintextAPIError
from aioesphomeapi._frame_helper.noise import APINoiseFrameHelper
from aioesphomeapi._frame_helper.noise_encryption import EncryptCipher
from aioesphomeapi._frame_helper.packets import (
    _cached_varuint_to_bytes as cached_varuint_to_bytes,
    _varuint_to_bytes as varuint_to_bytes,
)
from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.connection import ConnectionState
from aioesphomeapi.core import (
    APIConnectionError,
    BadMACAddressAPIError,
    BadNameAPIError,
    EncryptionHelloAPIError,
    HandshakeAPIError,
    InvalidEncryptionKeyAPIError,
    ProtocolAPIError,
    ReadFailedAPIError,
    SocketClosedAPIError,
)

from .common import (
    PREAMBLE,
    MockAPINoiseFrameHelper,
    _extract_encrypted_payload_from_handshake,
    _make_encrypted_packet,
    _make_encrypted_packet_from_encrypted_payload,
    _make_mock_connection,
    _make_noise_handshake_pkt,
    _make_noise_hello_pkt,
    _mock_responder_proto,
    get_mock_protocol,
    mock_data_received,
)

_PLAINTEXT_TESTS = [
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
        PREAMBLE + varuint_to_bytes(8192) + varuint_to_bytes(8192) + (b"\x42" * 8192),
        (b"\x42" * 8192),
        8192,
    ),
    (
        PREAMBLE + varuint_to_bytes(256) + varuint_to_bytes(256) + (b"\x42" * 256),
        (b"\x42" * 256),
        256,
    ),
]
if sys.platform != "win32":
    # pytest sets name of the test as an env var as win32 has a max char
    # limit that will cause the test to fail
    _PLAINTEXT_TESTS.extend(
        [
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
        ]
    )


@pytest.mark.parametrize(
    "in_bytes, pkt_data, pkt_type",
    _PLAINTEXT_TESTS,
)
async def test_plaintext_frame_helper(
    in_bytes: bytes, pkt_data: bytes, pkt_type: int
) -> None:
    for _ in range(3):
        connection, packets = _make_mock_connection()
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


@pytest.mark.parametrize(
    "in_bytes, pkt_data, pkt_type",
    _PLAINTEXT_TESTS,
)
async def test_plaintext_frame_helper_multiple_payloads_single_packet(
    in_bytes: bytes, pkt_data: bytes, pkt_type: int
) -> None:
    for _ in range(3):
        connection, packets = _make_mock_connection()
        helper = APIPlaintextFrameHelper(
            connection=connection, client_info="my client", log_name="test"
        )

        mock_data_received(helper, in_bytes)

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == pkt_type
        assert data == pkt_data

        # Make sure we correctly handle multiple payloads in a single packet
        mock_data_received(helper, in_bytes * 5)

        for i in range(5):
            pkt = packets.pop()
            type_, data = pkt

            assert type_ == pkt_type
            assert data == pkt_data

        helper.close()


@pytest.mark.parametrize(
    "byte_type",
    (bytes, bytearray, memoryview),
)
async def test_plaintext_frame_helper_protractor_event_loop(byte_type: Any) -> None:
    """Test the plaintext frame helper with the protractor event loop.

    With the protractor event loop, data_received is called with a bytearray
    instead of bytes.

    https://github.com/esphome/issues/issues/5117
    """
    for _ in range(3):
        connection, packets = _make_mock_connection()
        helper = APIPlaintextFrameHelper(
            connection=connection, client_info="my client", log_name="test"
        )
        in_bytes = byte_type(
            PREAMBLE + varuint_to_bytes(4) + varuint_to_bytes(100) + (b"\x42" * 4)
        )

        mock_data_received(helper, in_bytes)

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == 100
        assert data == b"\x42" * 4

        # Make sure we correctly handle fragments
        for i in range(len(in_bytes)):
            mock_data_received(helper, in_bytes[i : i + 1])

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == 100
        assert data == b"\x42" * 4


@pytest.mark.parametrize(
    "byte_type",
    (bytes, bytearray, memoryview),
)
async def test_noise_protector_event_loop(byte_type: Any) -> None:
    """Test the noise frame helper with the protractor event loop.

    With the protractor event loop, data_received is called with a bytearray
    instead of bytes.

    https://github.com/esphome/issues/issues/5117
    """
    outgoing_packets = [
        "010000",  # hello packet
        "010031001ed7f7bb0b74085418258ed5928931bc36ade7cf06937fcff089044d4ab142643f1b2c9935bb77696f23d930836737a4",
    ]
    incoming_packets = [
        "01000d01736572766963657465737400",
        "0100160148616e647368616b65204d4143206661696c757265",
    ]
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        expected_mac=None,
    )

    for pkt in outgoing_packets:
        helper.mock_write_frame(byte_type(bytes.fromhex(pkt)))

    for pkt in incoming_packets:
        mock_data_received(helper, byte_type(bytes.fromhex(pkt)))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        await helper.ready_future


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
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        expected_mac=None,
    )

    for pkt in outgoing_packets:
        helper.mock_write_frame(bytes.fromhex(pkt))

    for pkt in incoming_packets:
        mock_data_received(helper, bytes.fromhex(pkt))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        await helper.ready_future


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
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        expected_mac=None,
    )

    for pkt in outgoing_packets:
        helper.mock_write_frame(bytes.fromhex(pkt))

    for pkt in incoming_packets:
        in_pkt = bytes.fromhex(pkt)
        for i in range(len(in_pkt)):
            mock_data_received(helper, in_pkt[i : i + 1])

    with pytest.raises(InvalidEncryptionKeyAPIError):
        await helper.ready_future


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
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="wrongname",
        client_info="my client",
        log_name="test",
        expected_mac=None,
    )

    for pkt in outgoing_packets:
        helper.mock_write_frame(bytes.fromhex(pkt))

    for pkt in incoming_packets:
        mock_data_received(helper, bytes.fromhex(pkt))

    with pytest.raises(BadNameAPIError) as exc_info:
        await helper.ready_future
    assert exc_info.value.received_name == "servicetest"


async def test_noise_incorrect_mac():
    """Test we raise on bad name."""
    outgoing_packets = [
        "010000",  # hello packet
        "010031001ed7f7bb0b74085418258ed5928931bc36ade7cf06937fcff089044d4ab142643f1b2c9935bb77696f23d930836737a4",
    ]
    incoming_packets = [
        "01001f01706f6f6c686f757365383170726f78790032343463616230363439396300",
        "0100160148616e647368616b65204d4143206661696c757265",
    ]
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="poolhouse81proxy",
        client_info="my client",
        log_name="test",
        expected_mac="aabbccddeeff",
    )

    for pkt in outgoing_packets:
        helper.mock_write_frame(bytes.fromhex(pkt))

    for pkt in incoming_packets:
        mock_data_received(helper, bytes.fromhex(pkt))

    with pytest.raises(BadMACAddressAPIError) as exc_info:
        await helper.ready_future
    assert exc_info.value.received_name == "poolhouse81proxy"
    assert exc_info.value.received_mac == "244cab06499c"


async def test_noise_mac_in_exception():
    """Test the mac is in the exception when the key is wrong if available."""
    outgoing_packets = [
        "010000",  # hello packet
        "010031001ed7f7bb0b74085418258ed5928931bc36ade7cf06937fcff089044d4ab142643f1b2c9935bb77696f23d930836737a4",
    ]
    incoming_packets = [
        "01001f01706f6f6c686f757365383170726f78790032343463616230363439396300",
        "0100160148616e647368616b65204d4143206661696c757265",
    ]
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="poolhouse81proxy",
        client_info="my client",
        log_name="test",
        expected_mac=None,
    )

    for pkt in outgoing_packets:
        helper.mock_write_frame(bytes.fromhex(pkt))

    for pkt in incoming_packets:
        mock_data_received(helper, bytes.fromhex(pkt))

    with pytest.raises(InvalidEncryptionKeyAPIError) as exc_info:
        await helper.ready_future
    assert exc_info.value.received_name == "poolhouse81proxy"
    assert exc_info.value.received_mac == "244cab06499c"


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


async def test_noise_frame_helper_handshake_failure():
    """Test the noise frame helper handshake failure."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    writes = []

    def _writelines(data: Iterable[bytes]):
        writes.append(b"".join(data))

    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk=noise_psk,
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        writer=_writelines,
        expected_mac=None,
    )

    proto = _mock_responder_proto(psk_bytes)

    await asyncio.sleep(0)  # let the task run to read the hello packet

    assert len(writes) == 1
    handshake_pkt = writes.pop()
    encrypted_payload = _extract_encrypted_payload_from_handshake(handshake_pkt)

    decrypted = proto.read_message(encrypted_payload)
    assert decrypted == b""

    hello_pkt_with_header = _make_noise_hello_pkt(b"\x01servicetest\0")
    mock_data_received(helper, hello_pkt_with_header)

    error_pkt = b"\x01forced to fail"
    preamble = 1
    error_pkg_length = len(error_pkt)
    error_pkg_length_high = (error_pkg_length >> 8) & 0xFF
    error_pkg_length_low = error_pkg_length & 0xFF
    error_header = bytes((preamble, error_pkg_length_high, error_pkg_length_low))
    error_pkt_with_header = error_header + error_pkt

    mock_data_received(helper, error_pkt_with_header)

    with pytest.raises(HandshakeAPIError, match="forced to fail"):
        await helper.ready_future


async def test_noise_frame_helper_handshake_success_with_single_packet():
    """Test the noise frame helper handshake success with a single packet."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    writes = []

    def _writelines(data: Iterable[bytes]):
        writes.append(b"".join(data))

    connection, packets = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk=noise_psk,
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        writer=_writelines,
        expected_mac=None,
    )

    proto = _mock_responder_proto(psk_bytes)

    await asyncio.sleep(0)  # let the task run to read the hello packet

    assert len(writes) == 1
    handshake_pkt = writes.pop()

    encrypted_payload = _extract_encrypted_payload_from_handshake(handshake_pkt)
    decrypted = proto.read_message(encrypted_payload)
    assert decrypted == b""

    hello_pkt_with_header = _make_noise_hello_pkt(b"\x01servicetest\0")
    mock_data_received(helper, hello_pkt_with_header)

    handshake_with_header = _make_noise_handshake_pkt(proto)
    mock_data_received(helper, handshake_with_header)

    assert not writes

    await helper.ready_future
    helper.write_packets([(1, b"to device")], True)
    encrypted_packet = writes.pop()
    header = encrypted_packet[0:1]
    assert header == b"\x01"
    pkg_length_high = encrypted_packet[1]
    pkg_length_low = encrypted_packet[2]
    pkg_length = (pkg_length_high << 8) + pkg_length_low
    assert len(encrypted_packet) == 3 + pkg_length

    encrypt_cipher = EncryptCipher(proto.noise_protocol.cipher_state_encrypt)
    encrypted_packet = _make_encrypted_packet(encrypt_cipher, 42, b"from device")

    mock_data_received(helper, encrypted_packet)

    assert packets == [(42, b"from device")]
    helper.close()

    mock_data_received(helper, encrypted_packet)


async def test_noise_valid_encryption_invalid_payload(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test the noise with a packet that decrypts but is missing part of the payload."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    writes = []

    def _writelines(data: Iterable[bytes]):
        writes.append(b"".join(data))

    connection, packets = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk=noise_psk,
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        writer=_writelines,
        expected_mac=None,
    )

    proto = _mock_responder_proto(psk_bytes)

    await asyncio.sleep(0)  # let the task run to read the hello packet

    assert len(writes) == 1
    handshake_pkt = writes.pop()

    encrypted_payload = _extract_encrypted_payload_from_handshake(handshake_pkt)
    decrypted = proto.read_message(encrypted_payload)
    assert decrypted == b""

    hello_pkt_with_header = _make_noise_hello_pkt(b"\x01servicetest\0")
    mock_data_received(helper, hello_pkt_with_header)

    handshake_with_header = _make_noise_handshake_pkt(proto)
    mock_data_received(helper, handshake_with_header)

    assert not writes

    await helper.ready_future
    helper.write_packets([(1, b"to device")], True)
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
    # Trim the pre-encrypted payload to be missing the message length and payload
    encrypted_payload = proto.encrypt(bytes((msg_type_high, msg_type_low)))
    encrypted_packet = _make_encrypted_packet_from_encrypted_payload(encrypted_payload)

    mock_data_received(helper, encrypted_packet)

    assert packets == []
    assert connection.is_connected is False
    assert "Decrypted message too short" in caplog.text
    helper.close()


async def test_noise_valid_encryption_payload_short(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test the noise with a packet that has a short encrypted payload."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    writes = []

    def _writelines(data: Iterable[bytes]):
        writes.append(b"".join(data))

    connection, packets = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk=noise_psk,
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        writer=_writelines,
        expected_mac=None,
    )

    proto = _mock_responder_proto(psk_bytes)

    await asyncio.sleep(0)  # let the task run to read the hello packet

    assert len(writes) == 1
    handshake_pkt = writes.pop()

    encrypted_payload = _extract_encrypted_payload_from_handshake(handshake_pkt)
    decrypted = proto.read_message(encrypted_payload)
    assert decrypted == b""

    hello_pkt_with_header = _make_noise_hello_pkt(b"\x01servicetest\0")
    mock_data_received(helper, hello_pkt_with_header)

    handshake_with_header = _make_noise_handshake_pkt(proto)
    mock_data_received(helper, handshake_with_header)

    assert not writes

    await helper.ready_future
    helper.write_packets([(1, b"to device")], True)
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
    # Trim the pre-encrypted payload to be missing the payload
    encrypted_payload = proto.encrypt(
        bytes((msg_type_high, msg_type_low, pkg_length_high, pkg_length_low))
    )

    preamble = 1
    encrypted_pkg_length = len(encrypted_payload)
    encrypted_pkg_length -= 1
    encrypted_pkg_length_high = (encrypted_pkg_length >> 8) & 0xFF
    encrypted_pkg_length_low = encrypted_pkg_length & 0xFF
    encrypted_header = bytes(
        (preamble, encrypted_pkg_length_high, encrypted_pkg_length_low)
    )
    encrypted_packet = encrypted_header + encrypted_payload

    mock_data_received(helper, encrypted_packet)

    assert packets == []
    assert connection.is_connected is False
    assert "Encryption error" in caplog.text
    helper.close()


async def test_noise_frame_helper_bad_encryption(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test the noise frame helper closes connection on encryption error."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    writes = []

    def _writelines(data: Iterable[bytes]):
        writes.append(b"".join(data))

    connection, packets = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk=noise_psk,
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        writer=_writelines,
        expected_mac=None,
    )

    proto = _mock_responder_proto(psk_bytes)

    await asyncio.sleep(0)  # let the task run to read the hello packet

    assert len(writes) == 1
    handshake_pkt = writes.pop()

    encrypted_payload = _extract_encrypted_payload_from_handshake(handshake_pkt)
    decrypted = proto.read_message(encrypted_payload)
    assert decrypted == b""

    hello_pkt_with_header = _make_noise_hello_pkt(b"\x01servicetest\0")
    mock_data_received(helper, hello_pkt_with_header)

    handshake_with_header = _make_noise_handshake_pkt(proto)
    mock_data_received(helper, handshake_with_header)

    assert not writes

    await helper.ready_future
    helper.write_packets([(1, b"to device")], True)
    encrypted_packet = writes.pop()
    header = encrypted_packet[0:1]
    assert header == b"\x01"
    pkg_length_high = encrypted_packet[1]
    pkg_length_low = encrypted_packet[2]
    pkg_length = (pkg_length_high << 8) + pkg_length_low
    assert len(encrypted_packet) == 3 + pkg_length

    encrypted_packet = _make_encrypted_packet_from_encrypted_payload(b"corrupt")
    mock_data_received(helper, encrypted_packet)
    await asyncio.sleep(0)

    assert packets == []
    assert connection.is_connected is False
    assert "Encryption error" in caplog.text
    helper.close()


async def test_init_plaintext_with_wrong_preamble(
    conn: APIConnection, aiohappyeyeballs_start_connection
):
    loop = asyncio.get_running_loop()
    protocol = get_mock_protocol(conn)
    with patch.object(loop, "create_connection") as create_connection:
        create_connection.return_value = (MagicMock(), protocol)

        conn._socket = MagicMock()
        await conn._connect_init_frame_helper()
        loop.call_soon(conn._frame_helper.ready_future.set_result, None)
        conn.connection_state = ConnectionState.CONNECTED

    task = asyncio.create_task(conn._connect_hello_login(login=True))
    await asyncio.sleep(0)
    # The preamble should be \x00 but we send \x09
    mock_data_received(protocol, b"\x09\x00\x00")

    with pytest.raises(ProtocolAPIError):
        await task


async def test_init_noise_with_wrong_byte_marker(noise_conn: APIConnection) -> None:
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    protocol: APINoiseFrameHelper | None = None

    async def _create_connection(create, sock, *args, **kwargs):
        nonlocal protocol
        protocol = create()
        protocol.connection_made(transport)
        return transport, protocol

    with patch.object(loop, "create_connection", side_effect=_create_connection):
        task = asyncio.create_task(noise_conn._connect_init_frame_helper())
        await asyncio.sleep(0)

        assert protocol is not None
        assert isinstance(noise_conn._frame_helper, APINoiseFrameHelper)

        mock_data_received(protocol, b"\x02\x00\x00")

        with pytest.raises(ProtocolAPIError, match="Marker byte invalid"):
            await task


async def test_init_noise_with_plaintext_byte_marker(noise_conn: APIConnection) -> None:
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    protocol: APINoiseFrameHelper | None = None

    async def _create_connection(create, sock, *args, **kwargs):
        nonlocal protocol
        protocol = create()
        protocol.connection_made(transport)
        return transport, protocol

    with patch.object(loop, "create_connection", side_effect=_create_connection):
        task = asyncio.create_task(noise_conn._connect_init_frame_helper())
        await asyncio.sleep(0)

        assert protocol is not None
        assert isinstance(noise_conn._frame_helper, APINoiseFrameHelper)

        mock_data_received(protocol, b"\x00\x00\x00")

        with pytest.raises(
            EncryptionPlaintextAPIError, match="The device is using plaintext protocol"
        ):
            await task


async def test_noise_frame_helper_empty_hello():
    """Test empty hello with noise."""
    connection, _ = _make_mock_connection()
    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        expected_mac=None,
    )

    hello_pkt_with_header = _make_noise_hello_pkt(b"")

    mock_data_received(helper, hello_pkt_with_header)

    with pytest.raises(HandshakeAPIError, match="ServerHello is empty"):
        await helper.ready_future


async def test_noise_frame_helper_wrong_protocol():
    """Test noise with the wrong protocol."""
    connection, _ = _make_mock_connection()
    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
        expected_mac=None,
    )

    # wrong protocol 5 instead of 1
    hello_pkt_with_header = _make_noise_hello_pkt(b"\x05servicetest\0")

    mock_data_received(helper, hello_pkt_with_header)

    with pytest.raises(
        HandshakeAPIError, match="Unknown protocol selected by client 5"
    ):
        await helper.ready_future


async def test_init_noise_attempted_when_esp_uses_plaintext(
    noise_conn: APIConnection,
) -> None:
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    protocol: APINoiseFrameHelper | None = None

    async def _create_connection(create, sock, *args, **kwargs):
        nonlocal protocol
        protocol = create()
        protocol.connection_made(transport)
        return transport, protocol

    with patch.object(loop, "create_connection", side_effect=_create_connection):
        task = asyncio.create_task(noise_conn._connect_init_frame_helper())
        await asyncio.sleep(0)

        assert isinstance(noise_conn._frame_helper, APINoiseFrameHelper)
        protocol = noise_conn._frame_helper

        protocol.connection_lost(ConnectionResetError())

        with pytest.raises(
            EncryptionHelloAPIError, match="The connection dropped immediately"
        ):
            await task


async def test_eof_received_closes_connection(
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login
    assert protocol.eof_received() is False
    assert conn.is_connected is False
    with pytest.raises(SocketClosedAPIError, match="EOF received"):
        await connect_task


@pytest.mark.parametrize(
    ("exception_map"),
    [
        (OSError("original message"), ReadFailedAPIError),
        (APIConnectionError("original message"), APIConnectionError),
        (SocketClosedAPIError("original message"), SocketClosedAPIError),
    ],
)
async def test_connection_lost_closes_connection_and_logs(
    caplog: pytest.LogCaptureFixture,
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
    exception_map: tuple[Exception, Exception],
) -> None:
    exception, raised_exception = exception_map
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login
    protocol.connection_lost(exception)
    assert conn.is_connected is False
    assert "original message" in caplog.text
    with pytest.raises(raised_exception, match="original message"):
        await connect_task


@pytest.mark.parametrize(
    ("bad_psk", "error"),
    (
        ("dGhpc2lzbm90MzJieXRlcw==", "expected 32-bytes of base64 data"),
        ("QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc", "Malformed PSK"),
    ),
)
async def test_noise_bad_psks(bad_psk: str, error: str) -> None:
    """Test we raise on bad psks."""
    connection, _ = _make_mock_connection()
    with pytest.raises(InvalidEncryptionKeyAPIError, match=error):
        MockAPINoiseFrameHelper(
            connection=connection,
            noise_psk=bad_psk,
            expected_name="wrongname",
            client_info="my client",
            log_name="test",
            expected_mac=None,
        )
