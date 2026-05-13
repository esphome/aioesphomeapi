"""Benchmarks for noise."""

import asyncio
import base64
from collections.abc import AsyncIterator, Iterable

import pytest
import pytest_asyncio
from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aioesphomeapi._frame_helper.noise_encryption import EncryptCipher
from aioesphomeapi._frame_helper.packets import make_noise_packets

from ..common import (
    MockAPINoiseFrameHelper,
    _extract_encrypted_payload_from_handshake,
    _make_encrypted_packet,
    _make_mock_connection,
    _make_noise_handshake_pkt,
    _make_noise_hello_pkt,
    _mock_responder_proto,
    mock_data_received,
)

NOISE_PAYLOAD_SIZES = [0, 64, 128, 1024, 16 * 1024]


async def _make_ready_helper(
    writes: list[bytes],
) -> tuple[MockAPINoiseFrameHelper, EncryptCipher]:
    """Drive a noise frame helper through handshake.

    Returns the ready helper plus the responder side's encrypt cipher. The
    cipher is returned so encrypt-path benchmarks can exercise the underlying
    ChaCha20Poly1305 (and framing) without having to reach into the helper's
    private cdef state for its own encrypt cipher; either side's cipher does
    the same work per call.
    """
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)

    def _writelines(data: Iterable[bytes]) -> None:
        writes.append(b"".join(data))

    connection, _packets = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk=noise_psk,
        expected_name="servicetest",
        expected_mac=None,
        client_info="my client",
        log_name="test",
        writer=_writelines,
    )

    proto = _mock_responder_proto(psk_bytes)

    await asyncio.sleep(0)
    assert len(writes) == 1
    handshake_pkt = writes.pop()
    encrypted_payload = _extract_encrypted_payload_from_handshake(handshake_pkt)
    assert proto.read_message(encrypted_payload) == b""

    hello_pkt_with_header = _make_noise_hello_pkt(b"\x01servicetest\0")
    mock_data_received(helper, hello_pkt_with_header)

    handshake_with_header = _make_noise_handshake_pkt(proto)
    mock_data_received(helper, handshake_with_header)

    await helper.ready_future

    responder_encrypt = EncryptCipher(proto.noise_protocol.cipher_state_encrypt)
    return helper, responder_encrypt


@pytest_asyncio.fixture
async def ready_noise_helper() -> AsyncIterator[
    tuple[MockAPINoiseFrameHelper, EncryptCipher]
]:
    """Hand back a handshaken noise helper paired with a responder cipher."""
    writes: list[bytes] = []
    helper, encrypt_cipher = await _make_ready_helper(writes)
    try:
        yield helper, encrypt_cipher
    finally:
        helper.close()


@pytest.mark.parametrize("payload_size", NOISE_PAYLOAD_SIZES)
async def test_noise_messages(benchmark: BenchmarkFixture, payload_size: int) -> None:
    """Benchmark raw noise protocol."""
    noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    psk_bytes = base64.b64decode(noise_psk)
    writes = []

    def _writelines(data: Iterable[bytes]):
        writes.append(b"".join(data))

    connection, _packets = _make_mock_connection()

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk=noise_psk,
        expected_name="servicetest",
        expected_mac=None,
        client_info="my client",
        log_name="test",
        writer=_writelines,
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

    helper.write_packets([(1, b"to device")], True)

    def _empty_writelines(data: Iterable[bytes]):
        """Empty writelines."""

    helper._writelines = _empty_writelines

    payload = b"x" * payload_size
    encrypt_cipher = EncryptCipher(proto.noise_protocol.cipher_state_encrypt)

    @benchmark
    def process_encrypted_packets():
        for _ in range(100):
            helper.data_received(_make_encrypted_packet(encrypt_cipher, 42, payload))

    helper.close()


@pytest.mark.parametrize("payload_size", NOISE_PAYLOAD_SIZES)
async def test_noise_encrypt_cipher(
    benchmark: BenchmarkFixture,
    payload_size: int,
    ready_noise_helper: tuple[MockAPINoiseFrameHelper, EncryptCipher],
) -> None:
    """Benchmark raw EncryptCipher.encrypt across payload sizes.

    Isolates ChaCha20Poly1305 + nonce packing cost from framing overhead.
    """
    _, encrypt_cipher = ready_noise_helper
    payload = b"x" * payload_size

    @benchmark
    def encrypt_packets() -> None:
        for _ in range(100):
            encrypt_cipher.encrypt(payload)


@pytest.mark.parametrize("payload_size", NOISE_PAYLOAD_SIZES)
async def test_noise_make_packets(
    benchmark: BenchmarkFixture,
    payload_size: int,
    ready_noise_helper: tuple[MockAPINoiseFrameHelper, EncryptCipher],
) -> None:
    """Benchmark make_noise_packets, the full encrypt + framing cost."""
    _, encrypt_cipher = ready_noise_helper
    packet = (42, b"x" * payload_size)

    @benchmark
    def build_noise_packets() -> None:
        for _ in range(100):
            make_noise_packets([packet], encrypt_cipher)


@pytest.mark.parametrize("payload_size", NOISE_PAYLOAD_SIZES)
async def test_noise_write_packets(
    benchmark: BenchmarkFixture,
    payload_size: int,
    ready_noise_helper: tuple[MockAPINoiseFrameHelper, EncryptCipher],
) -> None:
    """Benchmark APINoiseFrameHelper.write_packets, the user-visible send path.

    This mirrors what happens for every command (light, switch, climate, etc.)
    sent over a noise connection.
    """
    helper, _ = ready_noise_helper

    def _drop(data: Iterable[bytes]) -> None:
        """Skip the actual write so we measure only frame construction."""

    helper._writelines = _drop
    packets: list[tuple[int, bytes]] = [(42, b"x" * payload_size)]

    @benchmark
    def write_packets() -> None:
        for _ in range(100):
            helper.write_packets(packets, False)
