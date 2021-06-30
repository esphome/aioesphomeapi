from typing import Optional


def varuint_to_bytes(value: int) -> bytes:
    if value <= 0x7F:
        return bytes([value])

    ret = bytes()
    while value:
        temp = value & 0x7F
        value >>= 7
        if value:
            ret += bytes([temp | 0x80])
        else:
            ret += bytes([temp])

    return ret


def bytes_to_varuint(value: bytes) -> Optional[int]:
    result = 0
    bitpos = 0
    for val in value:
        result |= (val & 0x7F) << bitpos
        bitpos += 7
        if (val & 0x80) == 0:
            return result
    return None
