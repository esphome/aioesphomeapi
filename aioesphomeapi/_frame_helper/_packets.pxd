# file: _packets.pxd
from libc.stdint cimport uint64_t
from libc.string cimport memcpy
from cpython.bytes cimport PyBytes_FromStringAndSize
from cpython cimport PyBytes_AsString
from .noise_encryption cimport EncryptCipher

# Function declarations
cdef inline char* encode_varint_direct(char* dst, uint64_t value) noexcept
cdef inline int varint_size(uint64_t value) noexcept

# Function to create plain text packets
cpdef bytes make_plain_text_packets(list packets)

# Function to create noise packets
cpdef bytes make_noise_packets(list packets, EncryptCipher encrypt_cipher)
