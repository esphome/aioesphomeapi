"""Tests for noise session resume."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from aioesphomeapi._frame_helper.noise_encryption import DecryptCipher, EncryptCipher
from aioesphomeapi._frame_helper.noise_resume import (
    RESUME_OFFER_SIZE,
    RawCipherState,
    build_resume_offer,
    derive_resume_keys,
    hkdf_noise,
    verify_confirm_mac,
)
from aioesphomeapi.api_pb2 import NoiseResumeTicket
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.core import ResumeAPIError

from .common import (
    MockAPINoiseFrameHelper,
    _make_mock_connection,
    get_mock_connection_params,
)

# Known-answer vectors shared with the device implementation
# (esphome tests/components/noise/test_noise_resume.cpp); the two must stay
# identical byte for byte or resumed sessions cannot interoperate.
KAT_SECRET = bytes(range(1, 33))
KAT_SESSION_ID = bytes(range(0xA0, 0xA8))
KAT_CLIENT_NONCE = bytes(range(0x10, 0x20))
KAT_SERVER_NONCE = bytes(range(0x30, 0x40))
KAT_OFFER_MAC = bytes.fromhex("a808eadbec81a7cbf4caaab80d7f9d01")
KAT_CONFIRM_MAC = bytes.fromhex("09a3703ec83477e945e7f1619d4f6a76")
KAT_K_C2D = bytes.fromhex(
    "d601e3c116a16466dbc59edd602a641ebef5119598d2f2471bc68c518fbeb723"
)
KAT_K_D2C = bytes.fromhex(
    "7f8d577e9fb4bbde86cda9f49b42e724c849ce89d8963f3c4b3f8f80c256ab65"
)


def test_kat_vectors_match_device_implementation() -> None:
    offer_mac = hkdf_noise(KAT_SECRET, b"offer" + KAT_SESSION_ID + KAT_CLIENT_NONCE)[0][
        :16
    ]
    assert offer_mac == KAT_OFFER_MAC
    assert verify_confirm_mac(
        KAT_SECRET, KAT_CLIENT_NONCE, KAT_SERVER_NONCE, KAT_CONFIRM_MAC
    )
    prologue = (
        b"NoiseAPIInit\x00\x29\x01" + KAT_SESSION_ID + KAT_CLIENT_NONCE + b"\xee" * 16
    )
    k_c2d, k_d2c = derive_resume_keys(
        KAT_SECRET, KAT_CLIENT_NONCE, KAT_SERVER_NONCE, prologue
    )
    assert k_c2d == KAT_K_C2D
    assert k_d2c == KAT_K_D2C


def test_build_resume_offer_layout() -> None:
    offer, client_nonce = build_resume_offer(KAT_SESSION_ID, KAT_SECRET)
    assert len(offer) == RESUME_OFFER_SIZE
    assert offer[0] == 0x01
    assert offer[1:9] == KAT_SESSION_ID
    assert offer[9:25] == client_nonce
    assert (
        offer[25:41]
        == hkdf_noise(KAT_SECRET, b"offer" + KAT_SESSION_ID + client_nonce)[0][:16]
    )


def _make_helper_with_ticket(
    writes: list[Any],
) -> tuple[MockAPINoiseFrameHelper, Any]:
    connection, packets = _make_mock_connection()

    def _writer(data: Any) -> None:
        writes.extend(data)

    helper = MockAPINoiseFrameHelper(
        connection=connection,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        expected_name="servicetest",
        expected_mac="11:22:33:44:55:aa",
        client_info="my client",
        log_name="test",
        writer=_writer,
        resume_ticket=(KAT_SESSION_ID, KAT_SECRET),
    )
    return helper, packets


def _extract_offer(writes: list[bytes]) -> bytes:
    """Pull the resume offer back out of the client's first write."""
    joined = b"".join(writes)
    assert joined[0] == 0x01
    hello_len = (joined[1] << 8) | joined[2]
    assert hello_len == RESUME_OFFER_SIZE
    return joined[3 : 3 + hello_len]


def _make_server_hello(ext: bytes = b"") -> bytes:
    return b"\x01servicetest\x00" + b"11:22:33:44:55:aa\x00" + ext


def _frame(payload: bytes) -> bytes:
    return bytes((0x01, (len(payload) >> 8) & 0xFF, len(payload) & 0xFF)) + payload


def _accept_ext(offer: bytes, server_nonce: bytes = KAT_SERVER_NONCE) -> bytes:
    client_nonce = offer[9:25]
    confirm = hkdf_noise(KAT_SECRET, b"confirm" + client_nonce + server_nonce)[0][:16]
    return b"\x01" + server_nonce + confirm


@pytest.mark.asyncio
async def test_resume_accept_establishes_session() -> None:
    writes: list[bytes] = []
    helper, packets = _make_helper_with_ticket(writes)
    offer = _extract_offer(writes)

    helper.data_received(_frame(_make_server_hello(_accept_ext(offer))))
    await asyncio.sleep(0)
    assert helper.ready_future.done()
    assert helper.ready_future.exception() is None

    # Device-side derivation must produce a working transport in both
    # directions
    client_nonce = offer[9:25]
    prologue = b"NoiseAPIInit" + bytes((0, RESUME_OFFER_SIZE)) + offer
    k_c2d, k_d2c = derive_resume_keys(
        KAT_SECRET, client_nonce, KAT_SERVER_NONCE, prologue
    )

    # device -> client
    device_send = EncryptCipher(RawCipherState(k_d2c))
    payload = b"\x00\x2a\x00\x03abc"  # type 42, len 3
    helper.data_received(_frame(device_send.encrypt(payload)))
    assert packets == [(42, b"abc")]

    # client -> device
    writes.clear()
    helper.write_packets([(42, b"hello")], True)
    device_recv = DecryptCipher(RawCipherState(k_c2d))
    joined = b"".join(writes)
    frame_len = (joined[1] << 8) | joined[2]
    decrypted = device_recv.decrypt(joined[3 : 3 + frame_len])
    assert decrypted[4:] == b"hello"


@pytest.mark.asyncio
async def test_resume_without_extension_falls_back_to_handshake() -> None:
    writes: list[bytes] = []
    helper, _ = _make_helper_with_ticket(writes)

    helper.data_received(_frame(_make_server_hello()))
    await asyncio.sleep(0)
    # Old firmware path: hello consumed, handshake still pending
    assert not helper.ready_future.done()


@pytest.mark.asyncio
async def test_resume_confirm_mac_mismatch_raises_resume_error() -> None:
    writes: list[bytes] = []
    helper, _ = _make_helper_with_ticket(writes)
    offer = _extract_offer(writes)

    ext = bytearray(_accept_ext(offer))
    ext[-1] ^= 0x01
    helper.data_received(_frame(_make_server_hello(bytes(ext))))
    await asyncio.sleep(0)
    with pytest.raises(ResumeAPIError):
        helper.ready_future.result()


@pytest.mark.asyncio
async def test_mac_failure_reject_after_offer_raises_resume_error() -> None:
    writes: list[bytes] = []
    helper, _ = _make_helper_with_ticket(writes)

    helper.data_received(_frame(_make_server_hello()))
    helper.data_received(_frame(b"\x01Handshake MAC failure"))
    await asyncio.sleep(0)
    with pytest.raises(ResumeAPIError):
        helper.ready_future.result()


@pytest.mark.asyncio
async def test_ticket_handler_stores_valid_ticket() -> None:
    params = get_mock_connection_params()
    connection = APIConnection(params, AsyncMock(), True, None)
    msg = NoiseResumeTicket()
    msg.session_id = KAT_SESSION_ID
    msg.secret = KAT_SECRET
    connection._handle_noise_resume_ticket_internal(msg)
    assert params.resume_ticket == (KAT_SESSION_ID, KAT_SECRET)

    bad = NoiseResumeTicket()
    bad.session_id = b"short"
    bad.secret = KAT_SECRET
    params.resume_ticket = None
    connection._handle_noise_resume_ticket_internal(bad)
    assert params.resume_ticket is None
