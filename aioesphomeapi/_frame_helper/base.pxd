
import cython


cdef bint TYPE_CHECKING

cdef class APIFrameHelper:

    cdef object _loop
    cdef object _on_pkt
    cdef object _on_error
    cdef object _transport
    cdef public object _writer
    cdef public object _ready_future
    cdef bytes _buffer
    cdef cython.uint _buffer_len
    cdef cython.uint _pos
    cdef object _client_info
    cdef str _log_name
    cdef object _debug_enabled

    @cython.locals(original_pos=cython.uint, new_pos=cython.uint)
    cdef bytes _read_exactly(self, int length)

    cdef _add_to_buffer(self, bytes data)

    @cython.locals(end_of_frame_pos=cython.uint)
    cdef _remove_from_buffer(self)
