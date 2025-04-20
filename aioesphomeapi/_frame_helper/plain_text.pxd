import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper
from ._packets cimport make_plain_text_packets

cdef bint TYPE_CHECKING


cdef class APIPlaintextFrameHelper(APIFrameHelper):

    cpdef void data_received(self, object data) except *

    cdef void _error_on_incorrect_preamble(self, int preamble) except *

    @cython.locals(
        result="unsigned int",
        bitpos="unsigned int",
        cstr="const unsigned char *",
        val="unsigned char",
        current_pos="unsigned int"
    )
    cdef int _read_varuint(self)

    cpdef void write_packets(self, list packets, bint debug_enabled) except *
