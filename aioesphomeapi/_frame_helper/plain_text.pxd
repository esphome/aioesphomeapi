from .base cimport BaseFrameHelper

cdef class APIPlaintextFrameHelper(BaseFrameHelper):

    cpdef write_packet(self, int type_, bytes data)

    cpdef data_received(self, bytes data)