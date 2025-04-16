from functools import lru_cache

from .noise_encryption import EncryptCipher

_int = int


def _varuint_to_bytes(value: _int) -> bytes:
    """Convert a varuint to bytes."""
    if value <= 0x7F:
        return bytes((value,))

    result = bytearray()
    while value:
        temp = value & 0x7F
        value >>= 7
        if value:
            result.append(temp | 0x80)
        else:
            result.append(temp)

    return bytes(result)


_cached_varuint_to_bytes = lru_cache(maxsize=1024)(_varuint_to_bytes)
varuint_to_bytes = _cached_varuint_to_bytes


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
        data_len = len(data)
        data_header = bytes(
            (
                (type_ >> 8) & 0xFF,
                type_ & 0xFF,
                (data_len >> 8) & 0xFF,
                data_len & 0xFF,
            )
        )
        frame = encrypt_cipher.encrypt(data_header + data)
        frame_len = len(frame)
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        out.append(header)
        out.append(frame)
    return out
