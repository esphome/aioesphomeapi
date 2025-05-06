from cpython.bytes cimport PyBytes_FromStringAndSize
from libc.stdint cimport uint64_t, uint32_t

cpdef bytes fast_pack_nonce(uint64_t q):
    cdef:
        char buf[12]
        uint32_t* first_part = <uint32_t*>buf  # Pointer to first 4 bytes
        uint64_t* second_part = <uint64_t*>(buf + 4)  # Pointer to next 8 bytes

    # Set first 4 bytes to zero
    first_part[0] = 0

    # Set the 8-byte uint64_t value
    second_part[0] = q

    # Create and return Python bytes object
    return PyBytes_FromStringAndSize(buf, 12)
