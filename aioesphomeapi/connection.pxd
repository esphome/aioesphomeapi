import cython

cdef dict MESSAGE_TYPE_TO_PROTO
cdef dict PROTO_TO_MESSAGE_TYPE

cdef set OPEN_STATES

cdef float KEEP_ALIVE_TIMEOUT_RATIO

cdef bint TYPE_CHECKING

cdef object DISCONNECT_REQUEST_MESSAGE
cdef object PING_REQUEST_MESSAGE
cdef object PING_RESPONSE_MESSAGE

cdef object DisconnectRequest
cdef object PingRequest
cdef object GetTimeRequest

cdef class APIConnection:

    cdef object _params
    cdef public object on_stop
    cdef object _on_stop_task
    cdef object _socket
    cdef object _frame_helper
    cdef public object api_version
    cdef object _connection_state
    cdef object _connect_complete
    cdef dict _message_handlers
    cdef public str log_name
    cdef set _read_exception_futures
    cdef object _ping_timer
    cdef object _pong_timer
    cdef float _keep_alive_interval
    cdef float _keep_alive_timeout
    cdef object _connect_task
    cdef object _fatal_exception
    cdef bint _expected_disconnect
    cdef object _loop
    cdef bint _send_pending_ping
    cdef public bint is_connected
    cdef public bint is_authenticated
    cdef bint _is_socket_open
    cdef object _debug_enabled

    cpdef send_message(self, object msg)

    @cython.locals(handlers=set)
    cpdef _process_packet(self, object msg_type_proto, object data)

    cpdef _async_cancel_pong_timer(self)

    cpdef _async_schedule_keep_alive(self, object now)

    cpdef _cleanup(self)

    cpdef _set_connection_state(self, object state)