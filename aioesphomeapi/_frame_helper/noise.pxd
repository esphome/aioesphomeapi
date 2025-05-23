import cython

from ..connection cimport APIConnection
from .base cimport APIFrameHelper
from .noise_encryption cimport EncryptCipher, DecryptCipher
from .packets cimport make_noise_packets

cdef bint TYPE_CHECKING

cdef unsigned int NOISE_STATE_HELLO
cdef unsigned int NOISE_STATE_HANDSHAKE
cdef unsigned int NOISE_STATE_READY
cdef unsigned int NOISE_STATE_CLOSED

cdef bytes NOISE_HELLO
cdef object InvalidTag
cdef object ESPHOME_NOISE_BACKEND

cdef class APINoiseFrameHelper(APIFrameHelper):

    cdef object _noise_psk
    cdef str _expected_name
    cdef str _expected_mac
    cdef unsigned int _state
    cdef str _server_mac
    cdef str _server_name
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
        server_name_i=int,
        mac_address_i=int,
        mac_address=str,
        server_name=str,
    )
    cdef void _handle_hello(self, bytes server_hello) except *

    cdef void _handle_handshake(self, bytes msg) except *

    cdef void _handle_closed(self, bytes frame) except *

    @cython.locals(handshake_frame=bytearray, frame_len="unsigned int")
    cdef void _send_hello_handshake(self) except *

    cdef void _setup_proto(self) except *

    @cython.locals(psk_bytes=bytes)
    cdef _decode_noise_psk(self)

    cpdef void write_packets(self, list packets, bint debug_enabled) except *

    cdef _error_on_incorrect_preamble(self, bytes msg)
