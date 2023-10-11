import cython


from .base cimport APIFrameHelper

cdef class APINoiseFrameHelper(APIFrameHelper):

    cdef object _noise_psk
    cdef object _expected_name
    cdef object _state
    cdef object _dispatch
    cdef object _server_name
    cdef object _proto
    cdef object _decrypt
    cdef object _encrypt
    cdef bint _is_ready
    
    cpdef data_received(self, bytes data)