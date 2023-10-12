import cython

from .base cimport APIFrameHelper


cdef bint TYPE_CHECKING
cdef object WRITE_EXCEPTIONS
cdef object bytes_to_varuint, varuint_to_bytes

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
