cdef object DNSAddress
cdef object DNSPointer
cdef unsigned int _TYPE_PTR

cdef dict _dispatchers


cdef void _dispatch(dict wakes, double now, list records) except *
