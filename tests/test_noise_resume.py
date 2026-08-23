"""Tests for noise session resume."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from aioesphomeapi._frame_helper.noise_encryption import DecryptCipher, EncryptCipher
from aioesphomeapi._frame_helper.noise_resume import (
    RESUME_OFFER_MAC_OFFSET,
    RESUME_OFFER_NONCE_OFFSET,
    RESUME_OFFER_SESSION_ID_OFFSET,
    RESUME_OFFER_SIZE,
    build_client_hello,
    build_resume_offer,
    derive_resume_keys,
    hkdf_noise,
    parse_resume_accept,
    verify_confirm_mac,
)
from aioesphomeapi.api_pb2 import NoiseResumeTicket
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.core import ResumeAPIError

from .common import (
    MockAPINoiseFrameHelper,
    _make_encrypted_packet,
    _make_mock_connection,
    _make_noise_hello_pkt,
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
    kat_offer = (
        b"\x01" + KAT_SESSION_ID + KAT_CLIENT_NONCE + b"\xee" * 16
    )  # MAC field fixed to 0xEE in the shared vectors
    _, prologue = build_client_hello(kat_offer)
    k_c2d, k_d2c = derive_resume_keys(
        KAT_SECRET, KAT_CLIENT_NONCE, KAT_SERVER_NONCE, prologue
    )
    assert k_c2d == KAT_K_C2D
    assert k_d2c == KAT_K_D2C


def test_build_resume_offer_layout() -> None:
    offer, client_nonce = build_resume_offer(KAT_SESSION_ID, KAT_SECRET)
    assert len(offer) == RESUME_OFFER_SIZE
    assert offer[0] == 0x01
    assert offer[RESUME_OFFER_SESSION_ID_OFFSET:RESUME_OFFER_NONCE_OFFSET] == (
        KAT_SESSION_ID
    )
    assert offer[RESUME_OFFER_NONCE_OFFSET:RESUME_OFFER_MAC_OFFSET] == client_nonce
    assert (
        offer[RESUME_OFFER_MAC_OFFSET:]
        == hkdf_noise(KAT_SECRET, b"offer" + KAT_SESSION_ID + client_nonce)[0][:16]
    )


def _make_helper_with_ticket() -> tuple[MockAPINoiseFrameHelper, Any, list[bytes]]:
    connection, packets = _make_mock_connection()
    writes: list[bytes] = []

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
    return helper, packets, writes


def _extract_offer(writes: list[bytes]) -> tuple[bytes, bytes]:
    """Pull the resume offer and client nonce out of the client's first write."""
    joined = b"".join(writes)
    assert joined[0] == 0x01
    hello_len = (joined[1] << 8) | joined[2]
    assert hello_len == RESUME_OFFER_SIZE
    offer = joined[3 : 3 + hello_len]
    return offer, offer[RESUME_OFFER_NONCE_OFFSET:RESUME_OFFER_MAC_OFFSET]


def _make_server_hello(ext: bytes = b"") -> bytes:
    return b"\x01servicetest\x00" + b"11:22:33:44:55:aa\x00" + ext


def _accept_ext(client_nonce: bytes, server_nonce: bytes = KAT_SERVER_NONCE) -> bytes:
    confirm = hkdf_noise(KAT_SECRET, b"confirm" + client_nonce + server_nonce)[0][:16]
    return b"\x01" + server_nonce + confirm


def test_parse_resume_accept() -> None:
    ext = _accept_ext(KAT_CLIENT_NONCE)
    assert parse_resume_accept(ext) == (KAT_SERVER_NONCE, KAT_CONFIRM_MAC)
    assert parse_resume_accept(b"") is None
    assert parse_resume_accept(ext[:-1]) is None
    assert parse_resume_accept(b"\x7f" + ext[1:]) is None


@pytest.mark.asyncio
async def test_resume_accept_establishes_session() -> None:
    helper, packets, writes = _make_helper_with_ticket()
    offer, client_nonce = _extract_offer(writes)

    helper.data_received(
        _make_noise_hello_pkt(_make_server_hello(_accept_ext(client_nonce)))
    )
    await asyncio.sleep(0)
    assert helper.ready_future.done()
    assert helper.ready_future.exception() is None

    # Device-side derivation must produce a working transport in both
    # directions
    _, prologue = build_client_hello(offer)
    k_c2d, k_d2c = derive_resume_keys(
        KAT_SECRET, client_nonce, KAT_SERVER_NONCE, prologue
    )

    # device -> client
    device_send = EncryptCipher.from_key(k_d2c)
    helper.data_received(_make_encrypted_packet(device_send, 42, b"abc"))
    assert packets == [(42, b"abc")]

    # client -> device
    writes.clear()
    helper.write_packets([(42, b"hello")], True)
    device_recv = DecryptCipher.from_key(k_c2d)
    joined = b"".join(writes)
    frame_len = (joined[1] << 8) | joined[2]
    decrypted = device_recv.decrypt(joined[3 : 3 + frame_len])
    assert decrypted[4:] == b"hello"


@pytest.mark.asyncio
async def test_resume_without_extension_falls_back_to_handshake() -> None:
    helper, _, _ = _make_helper_with_ticket()

    helper.data_received(_make_noise_hello_pkt(_make_server_hello()))
    await asyncio.sleep(0)
    # Old firmware path: hello consumed, handshake still pending
    assert not helper.ready_future.done()


@pytest.mark.asyncio
async def test_resume_confirm_mac_mismatch_raises_resume_error() -> None:
    helper, _, writes = _make_helper_with_ticket()
    _, client_nonce = _extract_offer(writes)

    ext = bytearray(_accept_ext(client_nonce))
    ext[-1] ^= 0x01
    helper.data_received(_make_noise_hello_pkt(_make_server_hello(bytes(ext))))
    await asyncio.sleep(0)
    with pytest.raises(ResumeAPIError):
        helper.ready_future.result()


@pytest.mark.asyncio
async def test_mac_failure_reject_after_offer_raises_resume_error() -> None:
    helper, _, _ = _make_helper_with_ticket()

    helper.data_received(_make_noise_hello_pkt(_make_server_hello()))
    helper.data_received(_make_noise_hello_pkt(b"\x01Handshake MAC failure"))
    await asyncio.sleep(0)
    with pytest.raises(ResumeAPIError):
        helper.ready_future.result()


@pytest.mark.asyncio
async def test_ticket_handler_stores_valid_ticket() -> None:
    params = get_mock_connection_params()
    params.noise_psk = "QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
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
