from libc.stdint cimport uint64_t
from libc.string cimport memcpy
from cpython.bytes cimport PyBytes_AsString, PyBytes_FromStringAndSize

cpdef bytes varuint_to_bytes(unsigned long long value):
    """Fast inline Protobuf Varint encoder returning Python bytes."""
    cdef uint64_t val = value
    cdef unsigned char buf[10]
    cdef int i = 0

    while val >= 0x80:
        buf[i] = <unsigned char>((val & 0x7F) | 0x80)
        val >>= 7
        i += 1

    buf[i] = <unsigned char>(val)
    i += 1

    return PyBytes_FromStringAndSize(<char *>buf, i)


cpdef bytes create_noise_payload(unsigned short type_, bytes data):
    """Create a noise payload with header, allocate once, and fill it with data."""
    cdef unsigned short data_len = len(data)
    cdef bytes payload = PyBytes_FromStringAndSize(NULL, 4 + data_len)

    # Get the pointer to the internal memory buffer of the bytes object
    cdef unsigned char* payload_ptr = <unsigned char*>PyBytes_AsString(payload)
    # Fill in the header
    payload_ptr[0] = (type_ >> 8) & 0xFF
    payload_ptr[1] = type_ & 0xFF
    payload_ptr[2] = (data_len >> 8) & 0xFF
    payload_ptr[3] = data_len & 0xFF

    # Copy the data into the payload after the header
    memcpy(payload_ptr + 4, <unsigned char*>data, data_len)
    return payload


cpdef bytes create_noise_data_header(int frame_len):
    """Create a noise outer header using PyBytes."""
    cdef bytes header = PyBytes_FromStringAndSize(NULL, 3)
    # Allocate space for 3 bytes (header)

    # Get the pointer to the internal memory buffer of the header
    cdef unsigned char* header_ptr = <unsigned char*>PyBytes_AsString(header)

    # Fill the header bytes
    header_ptr[0] = 0x01
    header_ptr[1] = (frame_len >> 8) & 0xFF
    header_ptr[2] = frame_len & 0xFF

    return header
