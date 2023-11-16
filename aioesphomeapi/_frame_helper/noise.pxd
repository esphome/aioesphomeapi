import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper


cdef bint TYPE_CHECKING

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
        header=bytes,
        preamble=cython.uint,
        msg_size_high=cython.uint,
        msg_size_low=cython.uint,
    )
    cpdef data_received(self, bytes data)

    @cython.locals(
        type_high=cython.uint,
        type_low=cython.uint
    )
    cpdef _handle_frame(self, bytes data)

    @cython.locals(
        type_="unsigned int",
        data=bytes,
        packet=tuple,
        data_len=cython.uint,
        frame=bytes,
        frame_len=cython.uint
    )
    cpdef write_packets(self, list packets)
