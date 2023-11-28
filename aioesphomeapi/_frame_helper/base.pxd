
import cython

from ..connection cimport APIConnection


cdef bint TYPE_CHECKING
cdef object WRITE_EXCEPTIONS

cdef class APIFrameHelper:

    cdef object _loop
    cdef APIConnection _connection
    cdef object _transport
    cdef public object _writer
    cdef public object _ready_future
    cdef bytes _buffer
    cdef unsigned int _buffer_len
    cdef unsigned int _pos
    cdef object _client_info
    cdef str _log_name

    cpdef set_log_name(self, str log_name)

    @cython.locals(original_pos="unsigned int", new_pos="unsigned int")
    cdef bytes _read(self, int length)

    @cython.locals(
        result="unsigned int",
        bitpos="unsigned int",
        val="unsigned char",
        current_pos="unsigned int"
    )
    cdef int _read_varuint(self)

    @cython.locals(bytes_data=bytes)
    cdef void _add_to_buffer(self, object data)

    @cython.locals(end_of_frame_pos="unsigned int")
    cdef void _remove_from_buffer(self)

    cpdef void write_packets(self, list packets, bint debug_enabled)

    cdef void _write_bytes(self, object data, bint debug_enabled)

    cdef get_handshake_future(self)
