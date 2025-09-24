import cython

from ._frame_helper.base cimport APIFrameHelper


cdef dict MESSAGE_TYPE_TO_PROTO
cdef dict PROTO_TO_MESSAGE_TYPE

cdef set OPEN_STATES

cdef float KEEP_ALIVE_TIMEOUT_RATIO
cdef object HANDSHAKE_TIMEOUT

cdef bint TYPE_CHECKING
cdef bint _WIN32

cdef object WRITE_EXCEPTIONS

cdef object DISCONNECT_REQUEST_MESSAGE
cdef tuple DISCONNECT_RESPONSE_MESSAGES
cdef tuple PING_REQUEST_MESSAGES
cdef tuple PING_RESPONSE_MESSAGES
cdef object NO_PASSWORD_AUTH_REQUEST

cdef object asyncio_timeout
cdef object CancelledError

cdef object AuthenticationRequest, AuthenticationResponse
cdef object DisconnectRequest
cdef object PingRequest
cdef object GetTimeRequest, GetTimeResponse
cdef object HelloRequest, HelloResponse

cdef object APIVersion

cdef object partial

cdef object hr

cdef object CONNECT_AND_SETUP_TIMEOUT, CONNECT_REQUEST_TIMEOUT

cdef object APIConnectionError
cdef object BadNameAPIError
cdef object HandshakeAPIError
cdef object PingFailedAPIError
cdef object ReadFailedAPIError
cdef object TimeoutAPIError
cdef object SocketAPIError
cdef object InvalidAuthAPIError
cdef object SocketClosedAPIError

cdef object astuple

cdef object CONNECTION_STATE_INITIALIZED
cdef object CONNECTION_STATE_HOST_RESOLVED
cdef object CONNECTION_STATE_SOCKET_OPENED
cdef object CONNECTION_STATE_HANDSHAKE_COMPLETE
cdef object CONNECTION_STATE_CONNECTED
cdef object CONNECTION_STATE_CLOSED

cdef object make_hello_request

cpdef void handle_timeout(object fut)
cpdef void handle_complex_message(
    object fut,
    list responses,
    object do_append,
    object do_stop,
    object resp,
)

cdef object _handle_timeout
cdef object _handle_complex_message

cdef tuple MESSAGE_NUMBER_TO_PROTO


@cython.dataclasses.dataclass
cdef class ConnectionParams:

    cdef public list addresses
    cdef public object port
    cdef public object password
    cdef public object client_info
    cdef public object keepalive
    cdef public object zeroconf_manager
    cdef public object noise_psk
    cdef public object expected_name
    cdef public object expected_mac
    cdef public object timezone


cdef class APIConnection:

    cdef ConnectionParams _params
    cdef public object on_stop
    cdef public object _socket
    cdef public APIFrameHelper _frame_helper
    cdef public object api_version
    cdef public object connection_state
    cdef public dict _message_handlers
    cdef public str log_name
    cdef set _read_exception_futures
    cdef object _ping_timer
    cdef object _pong_timer
    cdef float _keep_alive_interval
    cdef float _keep_alive_timeout
    cdef object _resolve_host_future
    cdef object _start_connect_future
    cdef object _finish_connect_future
    cdef public Exception _fatal_exception
    cdef bint _expected_disconnect
    cdef object _loop
    cdef bint _send_pending_ping
    cdef public bint is_connected
    cdef public bint _handshake_complete
    cdef bint _debug_enabled
    cdef public str received_name
    cdef public str connected_address
    cdef str _cached_timezone
    cdef list _addrs_info
    cdef bint _log_errors

    cpdef void send_message(self, object msg) except *

    @cython.locals(msg_type=tuple)
    cpdef void send_messages(self, tuple messages) except *

    @cython.locals(handlers=set, handlers_copy=set, klass_merge=tuple)
    cpdef void process_packet(
        self,
        unsigned int msg_type_proto,
        object data
    ) except *

    cdef void _async_cancel_pong_timer(self) except *

    cdef void _async_schedule_keep_alive(self, object now) except *

    cdef void _cleanup(self) except *

    cpdef set_log_name(self, str name)

    cdef _make_auth_request(self)

    cdef void _process_hello_resp(self, object resp) except *

    cdef void _process_login_response(self, object hello_response) except *

    cdef void _set_connection_state(self, object state) except *

    cpdef void report_fatal_error(self, Exception err) except *

    @cython.locals(handlers=set)
    cdef void _add_message_callback_without_remove(
        self,
        object on_message,
        tuple msg_types
    ) except *

    cpdef add_message_callback(self, object on_message, tuple msg_types)

    @cython.locals(handlers=set)
    cpdef void _remove_message_callback(
        self,
        object on_message,
        tuple msg_types
    ) except *

    cpdef void _handle_disconnect_request_internal(self, object msg) except *

    cpdef void _handle_ping_request_internal(self, object msg) except *

    cpdef void _handle_get_time_request_internal(self, object msg) except *

    cdef void _set_fatal_exception_if_unset(self, Exception err) except *

    cdef void _register_internal_message_handlers(self) except *

    cdef void _increase_recv_buffer_size(self) except *

    cdef void _set_start_connect_future(self) except *

    cdef void _set_finish_connect_future(self) except *
