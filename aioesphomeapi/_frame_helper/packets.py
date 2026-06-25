from functools import lru_cache

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
