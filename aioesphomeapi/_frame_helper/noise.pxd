import cython

from .base cimport APIFrameHelper


cdef object TYPE_CHECKING

cdef class APINoiseFrameHelper(APIFrameHelper):

    cdef object _noise_psk
    cdef object _expected_name
    cdef object _state
    cdef object _dispatch
    cdef object _server_name
    cdef object _proto
    cdef object _decrypt
    cdef object _encrypt
    cdef bint _is_ready

    @cython.locals(
        header=bytearray,
        preamble=cython.uint, 
        msg_size_high=cython.uint, 
        msg_size_low=cython.uint,
        end_of_frame_pos=cython.uint,
    )    
    cpdef data_received(self, bytes data)