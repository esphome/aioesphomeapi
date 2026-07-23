import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper
from .packets cimport make_plain_text_packets

cdef bint TYPE_CHECKING

cdef int _MAX_VARUINT_BYTES
cdef unsigned int _MAX_VARUINT_BITPOS
cdef int _MAX_PLAINTEXT_FRAME_SIZE
cdef int _VARUINT_INCOMPLETE
cdef int _VARUINT_PROTOCOL_ERROR


cdef class APIPlaintextFrameHelper(APIFrameHelper):

    cpdef void data_received(self, object data) except *

    cdef void _error_on_incorrect_preamble(self, int preamble) except *

    cdef void _close_on_oversized_varuint(self) except *

    @cython.locals(
        result="unsigned int",
        bitpos="unsigned int",
        cstr="const unsigned char *",
        val="unsigned char",
        current_pos="unsigned int"
    )
    cdef int _read_varuint(self) noexcept

    cpdef void write_packets(self, list packets, bint debug_enabled) except *
