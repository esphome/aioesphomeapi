"""Tests for the public aioesphomeapi.noise module."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
import pytest

from aioesphomeapi._frame_helper.noise_encryption import DecryptCipher, EncryptCipher
from aioesphomeapi.noise import NoiseHandshake, decode_noise_psk

from .common import _mock_responder_proto

if TYPE_CHECKING:
    from noise.connection import NoiseConnection

PSK = base64.b64encode(bytes(range(32))).decode()
OTHER_PSK = base64.b64encode(bytes(range(1, 33))).decode()
PROLOGUE = b"NoiseOTAInit-test-prologue"


def _make_responder(psk: str, prologue: bytes) -> NoiseConnection:
    return _mock_responder_proto(decode_noise_psk(psk), prologue)


def test_handshake_and_cipher_roundtrip() -> None:
    """Both handshake messages complete and the split ciphers interoperate."""
    handshake = NoiseHandshake(PSK, PROLOGUE)
    responder = _make_responder(PSK, PROLOGUE)

    assert not handshake.handshake_finished
    responder.read_message(handshake.write_message())
    handshake.read_message(bytes(responder.write_message()))
    assert handshake.handshake_finished

    encrypt_cipher, decrypt_cipher = handshake.get_ciphers()
    responder_decrypt = DecryptCipher(responder.noise_protocol.cipher_state_decrypt)
    responder_encrypt = EncryptCipher(responder.noise_protocol.cipher_state_encrypt)

    for i in range(5):
        plaintext = b"frame %d " % i + bytes(200)
        assert responder_decrypt.decrypt(encrypt_cipher.encrypt(plaintext)) == plaintext
        assert decrypt_cipher.decrypt(responder_encrypt.encrypt(plaintext)) == plaintext


def test_wrong_psk_fails_first_message() -> None:
    """A responder with a different PSK rejects the first handshake message."""
    handshake = NoiseHandshake(PSK, PROLOGUE)
    responder = _make_responder(OTHER_PSK, PROLOGUE)
    with pytest.raises(InvalidTag):
        responder.read_message(handshake.write_message())


def test_prologue_mismatch_fails_first_message() -> None:
    """A tampered prologue breaks the handshake even with the right PSK."""
    handshake = NoiseHandshake(PSK, PROLOGUE)
    responder = _make_responder(PSK, PROLOGUE + b"tampered")
    with pytest.raises(InvalidTag):
        responder.read_message(handshake.write_message())


def test_decrypt_rejects_tampered_frame() -> None:
    """A flipped ciphertext bit fails the AEAD check."""
    handshake = NoiseHandshake(PSK, PROLOGUE)
    responder = _make_responder(PSK, PROLOGUE)
    responder.read_message(handshake.write_message())
    handshake.read_message(bytes(responder.write_message()))
    encrypt_cipher, _ = handshake.get_ciphers()
    responder_decrypt = DecryptCipher(responder.noise_protocol.cipher_state_decrypt)

    ciphertext = bytearray(encrypt_cipher.encrypt(b"payload"))
    ciphertext[0] ^= 0x01
    with pytest.raises(InvalidTag):
        responder_decrypt.decrypt(bytes(ciphertext))


def test_decode_noise_psk_roundtrip() -> None:
    assert decode_noise_psk(PSK) == bytes(range(32))


@pytest.mark.parametrize(
    "bad_psk", ["not-valid-base64!!!", base64.b64encode(b"short").decode()]
)
def test_decode_noise_psk_rejects_bad_input(bad_psk: str) -> None:
    with pytest.raises(ValueError, match="expected base64-encoded 32-byte value"):
        decode_noise_psk(bad_psk)
