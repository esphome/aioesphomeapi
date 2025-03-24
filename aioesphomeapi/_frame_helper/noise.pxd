import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper


cdef bint TYPE_CHECKING

cdef unsigned int NOISE_STATE_HELLO
cdef unsigned int NOISE_STATE_HANDSHAKE
cdef unsigned int NOISE_STATE_READY
cdef unsigned int NOISE_STATE_CLOSED

cdef bytes NOISE_HELLO
cdef object PACK_NONCE
cdef object InvalidTag

cdef class EncryptCipher:

    cdef object _nonce
    cdef object _encrypt

    cdef bytes encrypt(self, object frame)

cdef class DecryptCipher:

    cdef object _nonce
    cdef object _decrypt

    cdef bytes decrypt(self, object frame)

cdef class APINoiseFrameHelper(APIFrameHelper):

    cdef object _noise_psk
    cdef str _expected_name
    cdef unsigned int _state
    cdef object _server_name
    cdef object _proto
    cdef EncryptCipher _encrypt_cipher
    cdef DecryptCipher _decrypt_cipher

    @cython.locals(
        header=bytes,
        preamble="unsigned char",
        header="const unsigned char *"
    )
    cpdef void data_received(self, object data) except *

    @cython.locals(
        msg=bytes,
        msg_type="unsigned int",
        payload=bytes,
        msg_length=Py_ssize_t,
        msg_cstr="const unsigned char *",
    )
    cdef void _handle_frame(self, bytes frame) except *

    @cython.locals(
        chosen_proto=char,
        server_name_i=int
    )
    cdef void _handle_hello(self, bytes server_hello) except *

    cdef void _handle_handshake(self, bytes msg) except *

    cdef void _handle_closed(self, bytes frame) except *

    @cython.locals(handshake_frame=bytearray, frame_len="unsigned int")
    cdef void _send_hello_handshake(self) except *

    cdef void _setup_proto(self) except *

    @cython.locals(psk_bytes=bytes)
    cdef _decode_noise_psk(self)

    @cython.locals(
        type_="unsigned int",
        data=bytes,
        data_header=bytes,
        packet=tuple,
        data_len=cython.uint,
        frame=bytes,
        frame_len=cython.uint,
    )
    cpdef void write_packets(self, tuple packets, bint debug_enabled) except *

    cdef _error_on_incorrect_preamble(self, bytes msg)
