from __future__ import annotations

import asyncio
import base64
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from noise.connection import NoiseConnection  # type: ignore[import-untyped]

from aioesphomeapi import APIConnection
from aioesphomeapi._frame_helper import APINoiseFrameHelper, APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.noise import ESPHOME_NOISE_BACKEND, NOISE_HELLO
from aioesphomeapi._frame_helper.plain_text import _bytes_to_varuint as bytes_to_varuint
from aioesphomeapi._frame_helper.plain_text import (
    _cached_bytes_to_varuint as cached_bytes_to_varuint,
)
from aioesphomeapi._frame_helper.plain_text import (
    _cached_varuint_to_bytes as cached_varuint_to_bytes,
)
from aioesphomeapi._frame_helper.plain_text import _varuint_to_bytes as varuint_to_bytes
from aioesphomeapi.connection import ConnectionState
from aioesphomeapi.core import (
    APIConnectionError,
    BadNameAPIError,
    HandshakeAPIError,
    InvalidEncryptionKeyAPIError,
    ProtocolAPIError,
    SocketClosedAPIError,
)

from .common import async_fire_time_changed, get_mock_protocol, utcnow

PREAMBLE = b"\x00"


def _make_mock_connection() -> tuple[APIConnection, list[tuple[int, bytes]]]:
    """Make a mock connection."""
    packets: list[tuple[int, bytes]] = []

    class MockConnection(APIConnection):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            """Swallow args."""

        def process_packet(self, type_: int, data: bytes):
            packets.append((type_, data))

        def report_fatal_error(self, exc: Exception):
            raise exc

    connection = MockConnection()
    return connection, packets


class MockAPINoiseFrameHelper(APINoiseFrameHelper):
    def mock_write_frame(self, frame: bytes) -> None:
        """Write a packet to the socket.

        The entire packet must be written in a single call to write.
        """
        frame_len = len(frame)
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        try:
            self._writer(header + frame)
        except (RuntimeError, ConnectionResetError, OSError) as err:
            raise SocketClosedAPIError(
                f"{self._log_name}: Error while writing data: {err}"
            ) from err


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
def test_plaintext_frame_helper(
    in_bytes: bytes, pkt_data: bytes, pkt_type: int
) -> None:
    for _ in range(3):
        connection, packets = _make_mock_connection()
        helper = APIPlaintextFrameHelper(
            connection=connection, client_info="my client", log_name="test"
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
        helper.close()


@pytest.mark.parametrize(
    "byte_type",
    (bytes, bytearray, memoryview),
)
def test_plaintext_frame_helper_protractor_event_loop(byte_type: Any) -> None:
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

        helper.data_received(in_bytes)

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == 100
        assert data == b"\x42" * 4

        # Make sure we correctly handle fragments
        for i in range(len(in_bytes)):
            helper.data_received(in_bytes[i : i + 1])

        pkt = packets.pop()
        type_, data = pkt

        assert type_ == 100
        assert data == b"\x42" * 4


@pytest.mark.asyncio
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
    )
    helper._transport = MagicMock()
    helper._writer = MagicMock()

    for pkt in outgoing_packets:
        helper.mock_write_frame(byte_type(bytes.fromhex(pkt)))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        for pkt in incoming_packets:
            helper.data_received(byte_type(bytes.fromhex(pkt)))

    with pytest.raises(InvalidEncryptionKeyAPIError):
        await helper.perform_handshake(30)


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
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
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
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
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
    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
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

    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
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


def test_bytes_to_varuint_invalid():
    assert bytes_to_varuint(b"\xFF") is None


@pytest.mark.asyncio
async def test_noise_frame_helper_handshake_failure():
    """Test the noise frame helper handshake failure."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    writes = []

    def _writer(data: bytes):
        writes.append(data)

    connection, _ = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
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
    writes = []

    def _writer(data: bytes):
        writes.append(data)

    connection, packets = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
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

    with pytest.raises(ProtocolAPIError, match="Connection closed"):
        helper.data_received(encrypted_header + encrypted_payload)


@pytest.mark.asyncio
async def test_init_plaintext_with_wrong_preamble(conn: APIConnection):
    loop = asyncio.get_event_loop()
    protocol = get_mock_protocol(conn)
    with patch.object(loop, "create_connection") as create_connection:
        create_connection.return_value = (MagicMock(), protocol)

        conn._socket = MagicMock()
        await conn._connect_init_frame_helper()
        loop.call_soon(conn._frame_helper._ready_future.set_result, None)
        conn.connection_state = ConnectionState.CONNECTED

    task = asyncio.create_task(conn._connect_hello_login(login=True))
    await asyncio.sleep(0)
    # The preamble should be \x00 but we send \x09
    protocol.data_received(b"\x09\x00\x00")

    with pytest.raises(ProtocolAPIError):
        await task


@pytest.mark.asyncio
async def test_init_noise_with_wrong_byte_marker(noise_conn: APIConnection) -> None:
    loop = asyncio.get_event_loop()
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

        protocol.data_received(b"\x00\x00\x00")

        with pytest.raises(ProtocolAPIError, match="Marker byte invalid"):
            await task


@pytest.mark.asyncio
async def test_noise_frame_helper_empty_hello():
    """Test empty hello with noise."""
    connection, _ = _make_mock_connection()
    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        client_info="my client",
        log_name="test",
    )
    helper._transport = MagicMock()
    helper._writer = MagicMock()

    handshake_task = asyncio.create_task(helper.perform_handshake(30))
    empty_hello_pkt = b""
    preamble = 1
    hello_pkg_length = len(empty_hello_pkt)
    hello_pkg_length_high = (hello_pkg_length >> 8) & 0xFF
    hello_pkg_length_low = hello_pkg_length & 0xFF
    hello_header = bytes((preamble, hello_pkg_length_high, hello_pkg_length_low))
    hello_pkt_with_header = hello_header + empty_hello_pkt

    with pytest.raises(HandshakeAPIError, match="ServerHello is empty"):
        helper.data_received(hello_pkt_with_header)

    with pytest.raises(HandshakeAPIError, match="ServerHello is empty"):
        await handshake_task


@pytest.mark.asyncio
async def test_init_noise_attempted_when_esp_uses_plaintext(
    noise_conn: APIConnection,
) -> None:
    loop = asyncio.get_event_loop()
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
            APIConnectionError, match="The connection dropped immediately"
        ):
            await task


@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_connection_lost_closes_connection_and_logs(
    caplog: pytest.LogCaptureFixture,
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login
    protocol.connection_lost(OSError("original message"))
    assert conn.is_connected is False
    assert "original message" in caplog.text
    with pytest.raises(APIConnectionError, match="original message"):
        await connect_task
