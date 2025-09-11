"""Benchmarks for noise."""

import asyncio
import base64
from collections.abc import Iterable

import pytest
from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aioesphomeapi._frame_helper.noise_encryption import EncryptCipher

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


@pytest.mark.parametrize("payload_size", [0, 64, 128, 1024, 16 * 1024])
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
