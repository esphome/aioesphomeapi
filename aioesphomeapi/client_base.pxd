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

cdef str _stringify_or_none(str value)

cdef class APIClientBase:

    cdef set _background_tasks
    cdef APIConnection _connection
    cdef bint _debug_enabled
    cdef object _loop
    cdef ConnectionParams _params
    cdef public str cached_name
    cdef public str log_name

    cpdef _set_log_name(self)

    cpdef APIConnection _get_connection(self)
