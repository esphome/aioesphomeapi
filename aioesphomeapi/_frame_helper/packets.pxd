from .noise_encryption cimport EncryptCipher

cdef object varuint_to_bytes

cpdef _varuint_to_bytes(int value)


@cython.locals(
    type_="unsigned int",
    data=bytes,
    packet=tuple,
    type_=object
)
cpdef list make_plain_text_packets(list packets) except *


@cython.locals(
    type_="unsigned int",
    data=bytes,
    data_header=bytes,
    packet=tuple,
    data_len=Py_ssize_t,
    frame=bytes,
    frame_len=Py_ssize_t,
)
cpdef list make_noise_packets(list packets, EncryptCipher encrypt_cipher) except *
