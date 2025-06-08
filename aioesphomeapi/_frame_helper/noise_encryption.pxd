import cython
from libc.stdint cimport uint64_t
from .pack cimport fast_pack_nonce

cdef object PACK_NONCE

cdef class EncryptCipher:

    cdef uint64_t _nonce
    cdef object _encrypt

    cpdef bytes encrypt(self, object frame)

cdef class DecryptCipher:

    cdef uint64_t _nonce
    cdef object _decrypt

    cdef bytes decrypt(self, object frame)
