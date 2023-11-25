import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper


cdef object varuint_to_bytes

cpdef _varuint_to_bytes(cython.int value)

cdef class APIPlaintextFrameHelper(APIFrameHelper):

    cpdef data_received(self, object data)

    cdef void _error_on_incorrect_preamble(self, int preamble)

    @cython.locals(
        type_="unsigned int",
        data=bytes,
        packet=tuple,
        type_=object
    )
    cpdef write_packets(self, list packets, bint debug_enabled)
