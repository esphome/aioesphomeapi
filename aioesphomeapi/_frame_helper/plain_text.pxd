import cython

from .base cimport APIFrameHelper


cdef bint TYPE_CHECKING
cdef object WRITE_EXCEPTIONS
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
    cpdef data_received(self, bytes data)
