import cython
from libc.stdint cimport uint64_t

cpdef bytes fast_pack_nonce(uint64_t q)
