import cython

cdef object PACK_NONCE

cdef class EncryptCipher:

    cdef object _nonce
    cdef object _encrypt

    cpdef bytes encrypt(self, object frame)

cdef class DecryptCipher:

    cdef object _nonce
    cdef object _decrypt

    cdef bytes decrypt(self, object frame)
