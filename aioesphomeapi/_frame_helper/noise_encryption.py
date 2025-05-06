from __future__ import annotations

from functools import partial
from struct import Struct
from typing import Any

from chacha20poly1305_reuseable import ChaCha20Poly1305Reusable
from noise.backends.default import DefaultNoiseBackend
from noise.backends.default.ciphers import ChaCha20Cipher, CryptographyCipher
from noise.state import CipherState

_bytes = bytes
_int = int

PACK_NONCE = partial(Struct("<LQ").pack, 0)

try:
    from .pack import fast_pack_nonce  # type: ignore[import-not-found, unused-ignore]
except ImportError:
    fast_pack_nonce = PACK_NONCE


class ChaCha20CipherReuseable(ChaCha20Cipher):  # type: ignore[misc]
    """ChaCha20 cipher that can be reused."""

    format_nonce = staticmethod(PACK_NONCE)

    @property
    def klass(self) -> type[ChaCha20Poly1305Reusable]:
        return ChaCha20Poly1305Reusable  # type: ignore[no-any-return, unused-ignore]


class ESPHomeNoiseBackend(DefaultNoiseBackend):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ciphers["ChaChaPoly"] = ChaCha20CipherReuseable


ESPHOME_NOISE_BACKEND = ESPHomeNoiseBackend()


class EncryptCipher:
    """Wrapper around the ChaCha20Poly1305 cipher for encryption."""

    __slots__ = ("_encrypt", "_nonce")

    def __init__(self, cipher_state: CipherState) -> None:
        """Initialize the cipher wrapper."""
        crypto_cipher: CryptographyCipher = cipher_state.cipher
        cipher: ChaCha20Poly1305Reusable = crypto_cipher.cipher
        self._nonce: _int = cipher_state.n
        self._encrypt = cipher.encrypt

    def encrypt(self, data: _bytes) -> bytes:
        """Encrypt a frame."""
        ciphertext = self._encrypt(fast_pack_nonce(self._nonce), data, None)
        self._nonce += 1
        return ciphertext  # type: ignore[no-any-return, unused-ignore]


class DecryptCipher:
    """Wrapper around the ChaCha20Poly1305 cipher for decryption."""

    __slots__ = ("_decrypt", "_nonce")

    def __init__(self, cipher_state: CipherState) -> None:
        """Initialize the cipher wrapper."""
        crypto_cipher: CryptographyCipher = cipher_state.cipher
        cipher: ChaCha20Poly1305Reusable = crypto_cipher.cipher
        self._nonce: _int = cipher_state.n
        self._decrypt = cipher.decrypt

    def decrypt(self, data: _bytes) -> bytes:
        """Decrypt a frame."""
        plaintext = self._decrypt(fast_pack_nonce(self._nonce), data, None)
        self._nonce += 1
        return plaintext  # type: ignore[no-any-return, unused-ignore]
