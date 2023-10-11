import cython

from .base cimport APIFrameHelper

cdef object TYPE_CHECKING

cdef class APIPlaintextFrameHelper(APIFrameHelper):

    @cython.locals(
        msg_type=bytes,
        length=bytes,
        init_bytes=bytearray, 
        end_of_frame_pos=cython.uint,
        length_int=cython.uint,
        preamble=cython.uint, 
        length_high=cython.uint, 
        maybe_msg_type=cython.uint
    )
    cpdef data_received(self, bytes data)