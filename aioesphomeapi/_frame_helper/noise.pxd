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
        preamble=char,
        msg_size_high=char,
        msg_size_low=char,
    )
    cpdef data_received(self, object data)

    @cython.locals(
        msg=bytes,
        type_high=char,
        type_low=char
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
        frame_len=cython.uint,
        type_=object
    )
    cpdef write_packets(self, list packets, bint debug_enabled)

    cdef _error_on_incorrect_preamble(self, bytes msg)
