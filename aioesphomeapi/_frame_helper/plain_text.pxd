import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper


cdef object varuint_to_bytes
cdef bint TYPE_CHECKING

cpdef _varuint_to_bytes(cython.int value)

cdef class APIPlaintextFrameHelper(APIFrameHelper):

    cpdef void data_received(self, object data) except *

    cdef void _error_on_incorrect_preamble(self, int preamble) except *

    @cython.locals(
        type_="unsigned int",
        data=bytes,
        packet=tuple,
        type_=object
    )
    cpdef void write_packets(self, list packets, bint debug_enabled) except *
