import cython

from .base cimport APIFrameHelper

cdef class APIPlaintextFrameHelper(APIFrameHelper):

    cpdef data_received(self, bytes data)