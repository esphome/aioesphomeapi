from functools import lru_cache

_int = int

# Cython 3.3 checks subscripted annotations against the .pxd signature and
# has no spelling for the Python int in tuple[int, bytes]; an alias it cannot
# resolve makes it read the argument as a plain list, as before.
Packet = tuple[int, bytes]


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


def make_plain_text_packets(packets: list[Packet]) -> list[bytes]:
    """Make a list of plain text packet."""
    out: list[bytes] = []
    for packet in packets:
        type_ = packet[0]
        data = packet[1]
        out.append(b"\0")
        out.append(varuint_to_bytes(len(data)))
        out.append(varuint_to_bytes(type_))
        if data:
            out.append(data)
    return out
