from functools import lru_cache


@lru_cache(maxsize=1024)
def varuint_to_bytes(value: int) -> bytes:
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


def create_noise_payload(type_: int, data: bytes) -> bytes:
    """Create a noise payload with header."""
    data_len = len(data)
    return (
        bytes(
            (
                (type_ >> 8) & 0xFF,
                type_ & 0xFF,
                (data_len >> 8) & 0xFF,
                data_len & 0xFF,
            )
        )
        + data
    )


def create_noise_data_header(frame_len: int) -> bytes:
    """Create a noise outer header."""
    return bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
