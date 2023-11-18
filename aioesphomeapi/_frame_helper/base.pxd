
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
    cdef object _debug_enabled

    cpdef set_log_name(self, str log_name)

    @cython.locals(original_pos="unsigned int", new_pos="unsigned int")
    cdef bytes _read_exactly(self, int length)

    @cython.locals(bytes_data=bytes)
    cdef _add_to_buffer(self, object data)

    @cython.locals(end_of_frame_pos="unsigned int")
    cdef _remove_from_buffer(self)

    cpdef write_packets(self, list packets)

    cdef _write_bytes(self, bytes data)
