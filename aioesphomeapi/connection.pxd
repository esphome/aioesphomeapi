import cython


cdef dict MESSAGE_TYPE_TO_PROTO
cdef dict PROTO_TO_MESSAGE_TYPE

cdef set OPEN_STATES

cdef float KEEP_ALIVE_TIMEOUT_RATIO

cdef bint TYPE_CHECKING

cdef object DISCONNECT_REQUEST_MESSAGE
cdef object DISCONNECT_RESPONSE_MESSAGE
cdef object PING_REQUEST_MESSAGE
cdef object PING_RESPONSE_MESSAGE

cdef object asyncio_timeout
cdef object CancelledError
cdef object asyncio_TimeoutError

cdef object ConnectResponse
cdef object DisconnectRequest
cdef object PingRequest
cdef object GetTimeRequest, GetTimeResponse

cdef object APIVersion

cdef object partial

cdef object hr

cdef object RESOLVE_TIMEOUT
cdef object CONNECT_AND_SETUP_TIMEOUT

cdef object APIConnectionError
cdef object BadNameAPIError
cdef object HandshakeAPIError
cdef object PingFailedAPIError
cdef object ReadFailedAPIError
cdef object TimeoutAPIError


cdef class APIConnection:

    cdef object _params
    cdef public object on_stop
    cdef object _on_stop_task
    cdef public object _socket
    cdef public object _frame_helper
    cdef public object api_version
    cdef public object connection_state
    cdef dict _message_handlers
    cdef public str log_name
    cdef set _read_exception_futures
    cdef object _ping_timer
    cdef object _pong_timer
    cdef float _keep_alive_interval
    cdef float _keep_alive_timeout
    cdef object _start_connect_task
    cdef object _finish_connect_task
    cdef object _fatal_exception
    cdef bint _expected_disconnect
    cdef object _loop
    cdef bint _send_pending_ping
    cdef public bint is_connected
    cdef bint _handshake_complete
    cdef object _debug_enabled

    cpdef send_message(self, object msg)

    @cython.locals(handlers=set, handlers_copy=set)
    cpdef _process_packet(self, object msg_type_proto, object data)

    cpdef _async_cancel_pong_timer(self)

    cpdef _async_schedule_keep_alive(self, object now)

    cpdef _cleanup(self)

    cpdef _set_connection_state(self, object state)

    cpdef _report_fatal_error(self, Exception err)

    @cython.locals(handlers=set)
    cpdef _add_message_callback_without_remove(self, object on_message, tuple msg_types)

    cpdef add_message_callback(self, object on_message, tuple msg_types)

    @cython.locals(handlers=set)
    cpdef _remove_message_callback(self, object on_message, tuple msg_types)

    cdef _send_messages(self, tuple messages)
