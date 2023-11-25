import cython

from ._frame_helper.base cimport APIFrameHelper


cdef dict MESSAGE_TYPE_TO_PROTO
cdef dict PROTO_TO_MESSAGE_TYPE
cdef tuple MESSAGE_TYPE_LOOKUP
cdef unsigned int MAX_MESSAGE_TYPE_INDEX

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
cdef object HelloRequest, HelloResponse

cdef object APIVersion

cdef object partial

cdef object hr

cdef object RESOLVE_TIMEOUT
cdef object CONNECT_AND_SETUP_TIMEOUT, CONNECT_REQUEST_TIMEOUT

cdef object APIConnectionError
cdef object BadNameAPIError
cdef object HandshakeAPIError
cdef object PingFailedAPIError
cdef object ReadFailedAPIError
cdef object TimeoutAPIError
cdef object SocketAPIError
cdef object InvalidAuthAPIError

cdef object astuple

cdef object CONNECTION_STATE_INITIALIZED
cdef object CONNECTION_STATE_SOCKET_OPENED
cdef object CONNECTION_STATE_HANDSHAKE_COMPLETE
cdef object CONNECTION_STATE_CONNECTED
cdef object CONNECTION_STATE_CLOSED

@cython.dataclasses.dataclass
cdef class ConnectionParams:
    cdef public str address
    cdef public object port
    cdef public object password
    cdef public object client_info
    cdef public object keepalive
    cdef public object zeroconf_manager
    cdef public object noise_psk
    cdef public object expected_name

cdef class APIConnection:

    cdef ConnectionParams _params
    cdef public object on_stop
    cdef public object _socket
    cdef public APIFrameHelper _frame_helper
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
    cdef bint _debug_enabled
    cdef public str received_name
    cdef public object resolved_addr_info

    cpdef send_message(self, object msg)

    cdef send_messages(self, tuple messages)

    @cython.locals(handlers=set, handlers_copy=set)
    cpdef void process_packet(self, unsigned int msg_type_proto, object data)

    cpdef _async_cancel_pong_timer(self)

    cpdef _async_schedule_keep_alive(self, object now)

    cpdef _cleanup(self)

    cpdef set_log_name(self, str name)

    cdef _make_connect_request(self)

    cdef _process_hello_resp(self, object resp)

    cdef _process_login_response(self, object hello_response)

    cpdef _set_connection_state(self, object state)

    cpdef report_fatal_error(self, Exception err)

    @cython.locals(handlers=set)
    cpdef _add_message_callback_without_remove(self, object on_message, tuple msg_types)

    cpdef add_message_callback(self, object on_message, tuple msg_types)

    @cython.locals(handlers=set)
    cpdef _remove_message_callback(self, object on_message, tuple msg_types)

    cpdef _handle_disconnect_request_internal(self, object msg)

    cpdef _handle_ping_request_internal(self, object msg)

    cpdef _handle_get_time_request_internal(self, object msg)
