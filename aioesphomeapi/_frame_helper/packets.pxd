import cython

cdef object varuint_to_bytes

cpdef _varuint_to_bytes(int value)


@cython.locals(
    type_="unsigned int",
    data=bytes,
    packet=tuple,
    type_=object
)
cpdef list make_plain_text_packets(list packets) except *
