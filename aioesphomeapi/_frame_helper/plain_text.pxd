import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper


cdef bint TYPE_CHECKING
cdef object bytes_to_varuint, varuint_to_bytes

cpdef _varuint_to_bytes(cython.int value)

@cython.locals(result=cython.int, bitpos=cython.int, val=cython.int)
cpdef _bytes_to_varuint(cython.bytes value)

cdef class APIPlaintextFrameHelper(APIFrameHelper):

    @cython.locals(
        msg_type=bytes,
        length=bytes,
        init_bytes=bytes,
        add_length=bytes,
        end_of_frame_pos=cython.uint,
        length_int=cython.uint,
        preamble=cython.uint,
        length_high=cython.uint,
        maybe_msg_type=cython.uint
    )
    cpdef data_received(self, object data)

    cdef _error_on_incorrect_preamble(self, object preamble)

    @cython.locals(
        type_="unsigned int",
        data=bytes,
        packet=tuple,
        type_=object
    )
    cpdef write_packets(self, list packets)
