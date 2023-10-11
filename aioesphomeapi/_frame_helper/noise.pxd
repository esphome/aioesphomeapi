import cython


from .base cimport BaseFrameHelper

cdef class APINoiseFrameHelper(BaseFrameHelper):

    cdef object _noise_psk
    cdef object _expected_name
    cdef object _state
    cdef object _dispatch
    cdef object _server_name
    cdef object _proto
    cdef object _decrypt
    cdef object _encrypt
    cdef bint _is_ready
    
    cpdef write_packet(self, int type_, bytes data)

    cpdef data_received(self, bytes data)