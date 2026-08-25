"""Synchronous Noise protocol primitives for ESPHome connections.

This module is deliberately standalone: it is not re-exported from
``aioesphomeapi.__init__`` and must not be imported at module level anywhere
else in this package. Importing it pulls in the noiseprotocol and
cryptography stacks, a cost that plaintext consumers (such as ``esphome
logs`` without an encryption key) must not pay. Import it lazily, only when
an encrypted session is actually needed.
"""

from __future__ import annotations

from noise.connection import NoiseConnection

from ._frame_helper.noise_encryption import (
    ESPHOME_NOISE_BACKEND,
    NOISE_PROTOCOL_NAME,
    DecryptCipher,
    EncryptCipher,
    decode_noise_psk,
)

__all__ = [
    "DecryptCipher",
    "EncryptCipher",
    "NoiseHandshake",
    "decode_noise_psk",
]


class NoiseHandshake:
    """Sans-IO initiator for Noise_NNpsk0_25519_ChaChaPoly_SHA256.

    Drives the two-message NNpsk0 handshake without any I/O; the caller moves
    the messages over its own transport, then takes the transport ciphers:

        handshake = NoiseHandshake(psk, prologue)
        send(handshake.write_message())
        handshake.read_message(receive())
        encrypt_cipher, decrypt_cipher = handshake.get_ciphers()

    A wrong PSK or mismatched prologue surfaces as
    ``cryptography.exceptions.InvalidTag`` from ``read_message``.
    """

    __slots__ = ("_ciphers", "_proto")

    def __init__(self, psk: str, prologue: bytes) -> None:
        """Initialize the handshake with a base64 PSK and a prologue."""
        proto = NoiseConnection.from_name(
            NOISE_PROTOCOL_NAME, backend=ESPHOME_NOISE_BACKEND
        )
        proto.set_as_initiator()
        proto.set_psks(decode_noise_psk(psk))
        proto.set_prologue(prologue)
        proto.start_handshake()
        self._proto = proto
        self._ciphers: tuple[EncryptCipher, DecryptCipher] | None = None

    def write_message(self) -> bytes:
        """Return the next handshake message to send to the responder."""
        return bytes(self._proto.write_message())

    def read_message(self, data: bytes) -> None:
        """Process a handshake message received from the responder."""
        self._proto.read_message(data)

    @property
    def handshake_finished(self) -> bool:
        """Return True once both handshake messages have been processed."""
        return bool(self._proto.handshake_finished)

    def get_ciphers(self) -> tuple[EncryptCipher, DecryptCipher]:
        """Return the (encrypt, decrypt) transport ciphers after the handshake.

        The pair is created once and returned again on later calls; each
        wrapper keeps its own nonce counter, so handing out fresh wrappers
        twice would silently reuse nonces under the same key.
        """
        if self._ciphers is None:
            if not self.handshake_finished:
                msg = "Handshake is not finished"
                raise RuntimeError(msg)
            noise_protocol = self._proto.noise_protocol
            self._ciphers = (
                EncryptCipher(noise_protocol.cipher_state_encrypt),
                DecryptCipher(noise_protocol.cipher_state_decrypt),
            )
        return self._ciphers
