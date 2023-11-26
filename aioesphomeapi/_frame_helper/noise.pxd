import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper


cdef bint TYPE_CHECKING

cdef unsigned int NOISE_STATE_HELLO
cdef unsigned int NOISE_STATE_HANDSHAKE
cdef unsigned int NOISE_STATE_READY
cdef unsigned int NOISE_STATE_CLOSED

cdef bytes NOISE_HELLO

cdef class APINoiseFrameHelper(APIFrameHelper):

    cdef object _noise_psk
    cdef str _expected_name
    cdef unsigned int _state
    cdef object _server_name
    cdef object _proto
    cdef object _decrypt
    cdef object _encrypt

    @cython.locals(
        header=bytes,
        preamble="unsigned char",
        msg_size_high="unsigned char",
        msg_size_low="unsigned char",
    )
    cpdef void data_received(self, object data)

    @cython.locals(
        msg=bytes,
        type_high="unsigned char",
        type_low="unsigned char"
    )
    cdef void _handle_frame(self, bytes frame)

    @cython.locals(
        chosen_proto=char,
        server_name_i=int
    )
    cdef void _handle_hello(self, bytes server_hello)

    cdef void _handle_handshake(self, bytes msg)

    cdef void _handle_closed(self, bytes frame)

    @cython.locals(handshake_frame=bytearray, frame_len="unsigned int")
    cdef void _send_hello_handshake(self)

    cdef void _setup_proto(self)

    @cython.locals(psk_bytes=bytes)
    cdef _decode_noise_psk(self)

    @cython.locals(
        type_="unsigned int",
        data=bytes,
        packet=tuple,
        data_len=cython.uint,
        frame=bytes,
        frame_len=cython.uint,
    )
    cpdef void write_packets(self, list packets, bint debug_enabled)

    cdef _error_on_incorrect_preamble(self, bytes msg)
