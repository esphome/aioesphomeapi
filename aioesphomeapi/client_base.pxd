import cython

from ._frame_helper.base cimport APIFrameHelper
from ._frame_helper.noise cimport APINoiseFrameHelper
from ._frame_helper.plain_text cimport APIPlaintextFrameHelper
from .connection cimport APIConnection, ConnectionParams


cdef object create_eager_task
cdef object APIConnectionError

cdef dict SUBSCRIBE_STATES_RESPONSE_TYPES

cdef bint TYPE_CHECKING

cdef object CameraImageResponse, CameraState

cdef object HomeassistantServiceCall

cdef object BluetoothLEAdvertisement

cdef object BluetoothDeviceConnectionResponse

cdef str _stringify_or_none(object value)

cdef class APIClientBase:

    cdef public set _background_tasks
    cdef public object _cached_device_info
    cdef public object _call_id_counter
    cdef public APIConnection _connection
    cdef public bint _debug_enabled
    cdef public object _loop
    cdef public dict _notify_callbacks
    cdef public ConnectionParams _params
    cdef public str cached_name
    cdef public str log_name

    cpdef _set_log_name(self)

    cpdef APIConnection _get_connection(self)
