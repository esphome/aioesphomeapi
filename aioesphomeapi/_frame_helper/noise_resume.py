"""Session resume for the noise frame helper.

The device issues a single-use NoiseResumeTicket after each encrypted
connection; the next connection offers it in the ClientHello body and both
sides derive the transport keys with HKDF-SHA256, skipping the X25519
handshake. Any mismatch falls back to the full handshake.

HKDF is the Noise construction, matching noise-c on the device:
    temp = HMAC-SHA256(key, data)
    out1 = HMAC-SHA256(temp, 0x01)
    out2 = HMAC-SHA256(temp, out1 || 0x02)

    offer_mac   = HKDF(secret, b"offer"   + session_id + client_nonce).out1[:16]
    confirm_mac = HKDF(secret, b"confirm" + client_nonce + server_nonce).out1[:16]
    k_c2d, k_d2c = HKDF(secret, b"keys" + client_nonce + server_nonce + SHA256(prologue))
"""

from __future__ import annotations

from hashlib import sha256
import hmac
from os import urandom

RESUME_OFFER_VERSION = 0x01
RESUME_ACCEPT_VERSION = 0x01
RESUME_SESSION_ID_SIZE = 8
RESUME_NONCE_SIZE = 16
RESUME_MAC_SIZE = 16
RESUME_SECRET_SIZE = 32

# version | session_id | client_nonce | offer_mac
RESUME_OFFER_SIZE = 1 + RESUME_SESSION_ID_SIZE + RESUME_NONCE_SIZE + RESUME_MAC_SIZE
RESUME_OFFER_SESSION_ID_OFFSET = 1
RESUME_OFFER_NONCE_OFFSET = RESUME_OFFER_SESSION_ID_OFFSET + RESUME_SESSION_ID_SIZE
RESUME_OFFER_MAC_OFFSET = RESUME_OFFER_NONCE_OFFSET + RESUME_NONCE_SIZE
# version | server_nonce | confirm_mac
RESUME_ACCEPT_SIZE = 1 + RESUME_NONCE_SIZE + RESUME_MAC_SIZE


def hkdf_noise(key: bytes, data: bytes) -> tuple[bytes, bytes]:
    """Noise-construction HKDF-SHA256 with two 32-byte outputs."""
    temp = hmac.new(key, data, sha256).digest()
    out1 = hmac.new(temp, b"\x01", sha256).digest()
    out2 = hmac.new(temp, out1 + b"\x02", sha256).digest()
    return out1, out2


def build_resume_offer(session_id: bytes, secret: bytes) -> tuple[bytes, bytes]:
    """Build the ClientHello resume offer; returns (offer, client_nonce)."""
    client_nonce = urandom(RESUME_NONCE_SIZE)
    offer_mac = hkdf_noise(secret, b"offer" + session_id + client_nonce)[0][
        :RESUME_MAC_SIZE
    ]
    offer = bytes((RESUME_OFFER_VERSION,)) + session_id + client_nonce + offer_mac
    return offer, client_nonce


def verify_confirm_mac(
    secret: bytes, client_nonce: bytes, server_nonce: bytes, confirm_mac: bytes
) -> bool:
    """Check the device's proof of ticket possession from the ServerHello."""
    expected = hkdf_noise(secret, b"confirm" + client_nonce + server_nonce)[0][
        :RESUME_MAC_SIZE
    ]
    return hmac.compare_digest(expected, confirm_mac)


def derive_resume_keys(
    secret: bytes, client_nonce: bytes, server_nonce: bytes, prologue: bytes
) -> tuple[bytes, bytes]:
    """Derive the transport keys; returns (k_c2d, k_d2c).

    k_c2d encrypts client-to-device traffic, k_d2c device-to-client.
    """
    prologue_hash = sha256(prologue).digest()
    return hkdf_noise(secret, b"keys" + client_nonce + server_nonce + prologue_hash)


def build_client_hello(offer: bytes) -> tuple[bytes, bytes]:
    r"""Build the ClientHello frame and matching prologue for an offer.

    An empty offer yields the classic b"\x01\x00\x00" / b"NoiseAPIInit\x00\x00".
    """
    offer_len = len(offer)
    body = bytes(((offer_len >> 8) & 0xFF, offer_len & 0xFF)) + offer
    return b"\x01" + body, b"NoiseAPIInit" + body


def parse_resume_accept(ext: bytes) -> tuple[bytes, bytes] | None:
    """Parse a ServerHello resume accept; (server_nonce, confirm_mac) or None."""
    if len(ext) < RESUME_ACCEPT_SIZE or ext[0] != RESUME_ACCEPT_VERSION:
        return None
    return (
        ext[1 : 1 + RESUME_NONCE_SIZE],
        ext[1 + RESUME_NONCE_SIZE : RESUME_ACCEPT_SIZE],
    )
