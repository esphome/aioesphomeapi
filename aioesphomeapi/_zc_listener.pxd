import cython


cdef unsigned int _TYPE_A
cdef unsigned int _TYPE_AAAA
cdef unsigned int _TYPE_PTR

cdef dict _dispatchers


@cython.locals(
    record_update=object,
    new_record=object,
    record_type="unsigned int",
    matched=object,
)
cdef void _dispatch(dict wakes, double now, list records) except *
