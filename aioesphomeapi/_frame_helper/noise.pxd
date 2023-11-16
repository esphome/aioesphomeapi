import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper


cdef bint TYPE_CHECKING

cdef unsigned int NOISE_STATE_HELLO
cdef unsigned int NOISE_STATE_HANDSHAKE
cdef unsigned int NOISE_STATE_READY
cdef unsigned int NOISE_STATE_CLOSED

cdef class APINoiseFrameHelper(APIFrameHelper):

    cdef object _noise_psk
    cdef object _expected_name
    cdef unsigned int _state
    cdef object _dispatch
    cdef object _server_name
    cdef object _proto
    cdef object _decrypt
    cdef object _encrypt

    @cython.locals(
        header=bytes,
        preamble=cython.uint,
        msg_size_high=cython.uint,
        msg_size_low=cython.uint,
    )
    cpdef data_received(self, object data)

    @cython.locals(
        type_high=cython.uint,
        type_low=cython.uint
    )
    cdef _handle_frame(self, bytes frame)

    cdef _handle_hello(self, bytes server_hello)

    cdef _handle_handshake(self, bytes msg)

    cdef _handle_closed(self, bytes frame)

    @cython.locals(
        type_="unsigned int",
        data=bytes,
        packet=tuple,
        data_len=cython.uint,
        frame=bytes,
        frame_len=cython.uint
    )
    cpdef write_packets(self, list packets)
