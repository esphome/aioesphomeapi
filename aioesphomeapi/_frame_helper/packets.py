from .noise_encryption import EncryptCipher
from .packet_helpers import (
    create_noise_data_header,
    create_noise_payload,
    varuint_to_bytes,
)

_cached_varuint_to_bytes = varuint_to_bytes


def make_plain_text_packets(packets: list[tuple[int, bytes]]) -> list[bytes]:
    """Make a list of plain text packet."""
    out: list[bytes] = []
    for packet in packets:
        type_: int = packet[0]
        data: bytes = packet[1]
        out.append(b"\0")
        out.append(varuint_to_bytes(len(data)))
        out.append(varuint_to_bytes(type_))
        if data:
            out.append(data)
    return out


def make_noise_packets(
    packets: list[tuple[int, bytes]], encrypt_cipher: EncryptCipher
) -> list[bytes]:
    """Make a list of noise packet."""
    out: list[bytes] = []
    for packet in packets:
        type_: int = packet[0]
        data: bytes = packet[1]
        frame = encrypt_cipher.encrypt(create_noise_payload(type_, data))
        out.append(create_noise_data_header(len(frame)))
        out.append(frame)
    return out
