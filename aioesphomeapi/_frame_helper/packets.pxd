import cython

from .noise_encryption cimport EncryptCipher
from ._packets cimport varuint_to_bytes
from ._packets cimport create_noise_payload
from ._packets cimport create_noise_data_header


@cython.locals(
    type_="unsigned short",
    data=bytes,
    packet=tuple,
)
cpdef list make_plain_text_packets(list packets) except *


@cython.locals(
    type_="unsigned short",
    data=bytes,
    packet=tuple,
)
cpdef list make_noise_packets(list packets, EncryptCipher encrypt_cipher) except *
