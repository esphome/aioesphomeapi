from libc.stdint cimport uint64_t
from libc.string cimport memcpy
from cpython.bytes cimport PyBytes_FromStringAndSize
from cpython cimport PyBytes_AsString
from .noise_encryption cimport EncryptCipher

cdef inline char* encode_varint_direct(char* dst, uint64_t value) noexcept:
    """Encodes a varint directly into the given buffer, returns pointer."""
    while value >= 0x80:
        dst[0] = <char>((value & 0x7F) | 0x80)
        dst += 1
        value >>= 7
    dst[0] = <char>(value)
    return dst + 1


cdef inline int varint_size(uint64_t value) noexcept:
    """Returns the number of bytes needed to encode `value` as a protobuf varint."""
    cdef int size = 1
    while value >= 0x80:
        value >>= 7
        size += 1
    return size


cpdef bytes make_plain_text_packets(list packets):
    """Construct a single bytes object for all packets (protobuf varint + raw bytes)."""
    cdef tuple packet
    cdef uint64_t type_
    cdef Py_ssize_t data_len, total_size = 0
    cdef const char* data_ptr
    cdef char* p
    cdef unsigned char protocol_marker_byte = 0x00

    # --- First pass: compute total size ---
    for packet in packets:
        type_ = packets[0]
        data_len = len(<bytes>packets[1])
        total_size += 1  # protocol marker
        total_size += varint_size(data_len)
        total_size += varint_size(type_)
        total_size += data_len

    # --- Allocate output buffer ---
    cdef bytes result = PyBytes_FromStringAndSize(NULL, total_size)
    p = PyBytes_AsString(result)

    # --- Second pass: write packets ---
    for packet in packets:
        type_ = packet[0]
        data_len = len(packet[1])
        data_ptr = PyBytes_AsString(<bytes>packet[1])

        p[0] = protocol_marker_byte
        p += 1

        p = encode_varint_direct(p, data_len)
        p = encode_varint_direct(p, type_)

        if data_len > 0:
            memcpy(p, data_ptr, data_len)
            p += data_len

    return result


cpdef bytes make_noise_packets(list packets, EncryptCipher encrypt_cipher):
    """Construct a single bytes object with all noise packets without using lists."""
    cdef tuple packet
    cdef int type_, data_len
    cdef const char* data_ptr
    cdef char* header_and_data_ptr
    cdef char* out_ptr
    cdef bytes out, data_and_header, frame
    cdef Py_ssize_t total_size = 0
    cdef Py_ssize_t frame_len
    cdef unsigned char protocol_marker_byte = 0x01  # Fixed protocol byte

    # --- First pass: calculate the total size of the output ---
    for packet in packets:
        type_ = packets[0]
        data_len = len(<bytes>packets[1])

        # Header (4 bytes: type_hi, type_lo, len_hi, len_lo)
        total_size += 4  # header size

        # Encrypted frame header (3 bytes)
        total_size += 3  # frame header size

        # Data + header size
        total_size += data_len

    # --- Preallocate the output buffer ---
    out = PyBytes_FromStringAndSize(NULL, total_size)
    out_ptr = PyBytes_AsString(out)

    # --- Second pass: populate the buffer with data ---
    for packet in packets:
        type_ = packet[0]
        data_len = len(packet[1])
        data_ptr = PyBytes_AsString(<bytes>packet[1])

        # Construct 4-byte data header: [type_hi, type_lo, len_hi, len_lo]
        data_and_header = PyBytes_FromStringAndSize(NULL, 4 + data_len)
        header_and_data_ptr = PyBytes_AsString(data_and_header)

        # Write header directly to buffer (4 bytes)
        (<unsigned char*>header_and_data_ptr)[0] = (type_ >> 8) & 0xFF
        (<unsigned char*>header_and_data_ptr)[1] = type_ & 0xFF
        (<unsigned char*>header_and_data_ptr)[2] = (data_len >> 8) & 0xFF
        (<unsigned char*>header_and_data_ptr)[3] = data_len & 0xFF

        # Copy data to buffer
        if data_len > 0:
            memcpy(header_and_data_ptr + 4, data_ptr, data_len)

        # Encrypt the frame (header + data)
        frame = <bytes>encrypt_cipher.encrypt(data_and_header)
        frame_len = len(frame)

        # Write the frame header: [0x01, frame_len_hi, frame_len_lo]
        out_ptr[0] = protocol_marker_byte
        out_ptr[1] = (frame_len >> 8) & 0xFF
        out_ptr[2] = frame_len & 0xFF

        # Move pointer after header
        out_ptr += 3

        # Copy encrypted frame into output
        memcpy(out_ptr, PyBytes_AsString(frame), frame_len)

        # Move pointer after frame
        out_ptr += frame_len

    return out
