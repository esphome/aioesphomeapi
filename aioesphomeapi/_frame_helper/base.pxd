
import cython


cdef class APIFrameHelper:

    cdef object _loop
    cdef object _on_pkt
    cdef object _on_error
    cdef object _transport
    cdef object _writer
    cdef object _ready_future
    cdef bytearray _buffer
    cdef cython.uint _buffer_len
    cdef cython.uint _pos
    cdef object _client_info
    cdef str _log_name
    cdef object _debug_enabled

    @cython.locals(original_pos=int)
    cdef _read_exactly(self, int length)