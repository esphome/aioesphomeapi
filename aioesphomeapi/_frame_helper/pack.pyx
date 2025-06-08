from cpython.bytes cimport PyBytes_FromStringAndSize
from libc.stdint cimport uint64_t

cpdef bytes fast_pack_nonce(uint64_t q):
    cdef:
        char buf[12]
        char *p = buf

    # First 4 bytes are zero
    p[0] = p[1] = p[2] = p[3] = 0

    # q (uint64_t) in little-endian
    p[4] = <char>(q & 0xFF)
    p[5] = <char>((q >> 8) & 0xFF)
    p[6] = <char>((q >> 16) & 0xFF)
    p[7] = <char>((q >> 24) & 0xFF)
    p[8] = <char>((q >> 32) & 0xFF)
    p[9] = <char>((q >> 40) & 0xFF)
    p[10] = <char>((q >> 48) & 0xFF)
    p[11] = <char>((q >> 56) & 0xFF)

    return PyBytes_FromStringAndSize(buf, 12)
