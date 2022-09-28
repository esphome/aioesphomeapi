from .api_pb2 import (  # type: ignore
    BinarySensorStateResponse,
    BluetoothConnectionsFreeResponse,
    BluetoothDeviceConnectionResponse,
    BluetoothDeviceRequest,
    BluetoothGATTGetServicesDoneResponse,
    BluetoothGATTGetServicesRequest,
    BluetoothGATTGetServicesResponse,
    BluetoothGATTNotifyDataResponse,
    BluetoothGATTNotifyRequest,
    BluetoothGATTReadDescriptorRequest,
    BluetoothGATTReadRequest,
    BluetoothGATTReadResponse,
    BluetoothGATTWriteDescriptorRequest,
    BluetoothGATTWriteRequest,
    BluetoothLEAdvertisementResponse,
    ButtonCommandRequest,
    CameraImageRequest,
    CameraImageResponse,
    ClimateCommandRequest,
    ClimateStateResponse,
    ConnectRequest,
    ConnectResponse,
    CoverCommandRequest,
    CoverStateResponse,
    DeviceInfoRequest,
    DeviceInfoResponse,
    DisconnectRequest,
    DisconnectResponse,
    ExecuteServiceRequest,
    FanCommandRequest,
    FanStateResponse,
    GetTimeRequest,
    GetTimeResponse,
    HelloRequest,
    HelloResponse,
    HomeassistantServiceResponse,
    HomeAssistantStateResponse,
    LightCommandRequest,
    LightStateResponse,
    ListEntitiesBinarySensorResponse,
    ListEntitiesButtonResponse,
    ListEntitiesCameraResponse,
    ListEntitiesClimateResponse,
    ListEntitiesCoverResponse,
    ListEntitiesDoneResponse,
    ListEntitiesFanResponse,
    ListEntitiesLightResponse,
    ListEntitiesLockResponse,
    ListEntitiesMediaPlayerResponse,
    ListEntitiesNumberResponse,
    ListEntitiesRequest,
    ListEntitiesSelectResponse,
    ListEntitiesSensorResponse,
    ListEntitiesServicesResponse,
    ListEntitiesSirenResponse,
    ListEntitiesSwitchResponse,
    ListEntitiesTextSensorResponse,
    LockCommandRequest,
    LockStateResponse,
    MediaPlayerCommandRequest,
    MediaPlayerStateResponse,
    NumberCommandRequest,
    NumberStateResponse,
    PingRequest,
    PingResponse,
    SelectCommandRequest,
    SelectStateResponse,
    SensorStateResponse,
    SirenCommandRequest,
    SirenStateResponse,
    SubscribeBluetoothConnectionsFreeRequest,
    SubscribeBluetoothLEAdvertisementsRequest,
    SubscribeHomeassistantServicesRequest,
    SubscribeHomeAssistantStateResponse,
    SubscribeHomeAssistantStatesRequest,
    SubscribeLogsRequest,
    SubscribeLogsResponse,
    SubscribeStatesRequest,
    SwitchCommandRequest,
    SwitchStateResponse,
    TextSensorStateResponse,
)


class APIConnectionError(Exception):
    pass


class InvalidAuthAPIError(APIConnectionError):
    pass


class ResolveAPIError(APIConnectionError):
    pass


class ProtocolAPIError(APIConnectionError):
    pass


class RequiresEncryptionAPIError(ProtocolAPIError):
    pass


class SocketAPIError(APIConnectionError):
    pass


class SocketClosedAPIError(SocketAPIError):
    pass


class HandshakeAPIError(APIConnectionError):
    pass


class BadNameAPIError(APIConnectionError):
    """Raised when a name received from the remote but does not much the expected name."""

    def __init__(self, msg: str, received_name: str) -> None:
        super().__init__(msg)
        self.received_name = received_name


class InvalidEncryptionKeyAPIError(HandshakeAPIError):
    pass


class PingFailedAPIError(APIConnectionError):
    pass


class TimeoutAPIError(APIConnectionError):
    pass


class ReadFailedAPIError(APIConnectionError):
    pass


MESSAGE_TYPE_TO_PROTO = {
    1: HelloRequest,
    2: HelloResponse,
    3: ConnectRequest,
    4: ConnectResponse,
    5: DisconnectRequest,
    6: DisconnectResponse,
    7: PingRequest,
    8: PingResponse,
    9: DeviceInfoRequest,
    10: DeviceInfoResponse,
    11: ListEntitiesRequest,
    12: ListEntitiesBinarySensorResponse,
    13: ListEntitiesCoverResponse,
    14: ListEntitiesFanResponse,
    15: ListEntitiesLightResponse,
    16: ListEntitiesSensorResponse,
    17: ListEntitiesSwitchResponse,
    18: ListEntitiesTextSensorResponse,
    19: ListEntitiesDoneResponse,
    20: SubscribeStatesRequest,
    21: BinarySensorStateResponse,
    22: CoverStateResponse,
    23: FanStateResponse,
    24: LightStateResponse,
    25: SensorStateResponse,
    26: SwitchStateResponse,
    27: TextSensorStateResponse,
    28: SubscribeLogsRequest,
    29: SubscribeLogsResponse,
    30: CoverCommandRequest,
    31: FanCommandRequest,
    32: LightCommandRequest,
    33: SwitchCommandRequest,
    34: SubscribeHomeassistantServicesRequest,
    35: HomeassistantServiceResponse,
    36: GetTimeRequest,
    37: GetTimeResponse,
    38: SubscribeHomeAssistantStatesRequest,
    39: SubscribeHomeAssistantStateResponse,
    40: HomeAssistantStateResponse,
    41: ListEntitiesServicesResponse,
    42: ExecuteServiceRequest,
    43: ListEntitiesCameraResponse,
    44: CameraImageResponse,
    45: CameraImageRequest,
    46: ListEntitiesClimateResponse,
    47: ClimateStateResponse,
    48: ClimateCommandRequest,
    49: ListEntitiesNumberResponse,
    50: NumberStateResponse,
    51: NumberCommandRequest,
    52: ListEntitiesSelectResponse,
    53: SelectStateResponse,
    54: SelectCommandRequest,
    55: ListEntitiesSirenResponse,
    56: SirenStateResponse,
    57: SirenCommandRequest,
    58: ListEntitiesLockResponse,
    59: LockStateResponse,
    60: LockCommandRequest,
    61: ListEntitiesButtonResponse,
    62: ButtonCommandRequest,
    63: ListEntitiesMediaPlayerResponse,
    64: MediaPlayerStateResponse,
    65: MediaPlayerCommandRequest,
    66: SubscribeBluetoothLEAdvertisementsRequest,
    67: BluetoothLEAdvertisementResponse,
    68: BluetoothDeviceRequest,
    69: BluetoothDeviceConnectionResponse,
    70: BluetoothGATTGetServicesRequest,
    71: BluetoothGATTGetServicesResponse,
    72: BluetoothGATTGetServicesDoneResponse,
    73: BluetoothGATTReadRequest,
    74: BluetoothGATTReadResponse,
    75: BluetoothGATTWriteRequest,
    76: BluetoothGATTReadDescriptorRequest,
    77: BluetoothGATTWriteDescriptorRequest,
    78: BluetoothGATTNotifyRequest,
    79: BluetoothGATTNotifyDataResponse,
    80: SubscribeBluetoothConnectionsFreeRequest,
    81: BluetoothConnectionsFreeResponse,
}
