import re

from aioesphomeapi.model import BluetoothGATTError

from .api_pb2 import (  # type: ignore
    BinarySensorStateResponse,
    BluetoothConnectionsFreeResponse,
    BluetoothDeviceClearCacheResponse,
    BluetoothDeviceConnectionResponse,
    BluetoothDevicePairingResponse,
    BluetoothDeviceRequest,
    BluetoothDeviceUnpairingResponse,
    BluetoothGATTErrorResponse,
    BluetoothGATTGetServicesDoneResponse,
    BluetoothGATTGetServicesRequest,
    BluetoothGATTGetServicesResponse,
    BluetoothGATTNotifyDataResponse,
    BluetoothGATTNotifyRequest,
    BluetoothGATTNotifyResponse,
    BluetoothGATTReadDescriptorRequest,
    BluetoothGATTReadRequest,
    BluetoothGATTReadResponse,
    BluetoothGATTWriteDescriptorRequest,
    BluetoothGATTWriteRequest,
    BluetoothGATTWriteResponse,
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
    SubscribeVoiceAssistantRequest,
    SwitchCommandRequest,
    SwitchStateResponse,
    TextSensorStateResponse,
    UnsubscribeBluetoothLEAdvertisementsRequest,
    VoiceAssistantEventResponse,
    VoiceAssistantRequest,
    VoiceAssistantResponse,
)

TWO_CHAR = re.compile(r".{2}")

# Taken from esp_gatt_status_t in esp_gatt_defs.h
ESPHOME_GATT_ERRORS = {
    -1: "Not connected",  # Custom ESPHome error
    1: "Invalid handle",
    2: "Read not permitted",
    3: "Write not permitted",
    4: "Invalid PDU",
    5: "Insufficient authentication",
    6: "Request not supported",
    7: "Invalid offset",
    8: "Insufficient authorization",
    9: "Prepare queue full",
    10: "Attribute not found",
    11: "Attribute not long",
    12: "Insufficient key size",
    13: "Invalid attribute length",
    14: "Unlikely error",
    15: "Insufficient encryption",
    16: "Unsupported group type",
    17: "Insufficient resources",
    128: "Application error",
    129: "Internal error",
    130: "Wrong state",
    131: "Database full",
    132: "Busy",
    133: "Error",
    134: "Command started",
    135: "Illegal parameter",
    136: "Pending",
    137: "Auth fail",
    138: "More",
    139: "Invalid configuration",
    140: "Service started",
    141: "Encrypted no mitm",
    142: "Not encrypted",
    143: "Congested",
    144: "Duplicate registration",
    145: "Already open",
    146: "Cancel",
    224: "Stack RSP",
    225: "App RSP",
    239: "Unknown error",
    253: "CCC config error",
    254: "Procedure already in progress",
    255: "Out of range",
}


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


def to_human_readable_address(address: int) -> str:
    """Convert a MAC address to a human readable format."""
    return ":".join(TWO_CHAR.findall(f"{address:012X}"))


def to_human_readable_gatt_error(error: int) -> str:
    """Convert a GATT error to a human readable format."""
    return ESPHOME_GATT_ERRORS.get(error, "Unknown error")


class BluetoothGATTAPIError(APIConnectionError):
    def __init__(self, error: BluetoothGATTError) -> None:
        super().__init__(
            f"Bluetooth GATT Error "
            f"address={to_human_readable_address(error.address)} "
            f"handle={error.handle} "
            f"error={error.error} "
            f"description={to_human_readable_gatt_error(error.error)}"
        )
        self.error = error


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
    82: BluetoothGATTErrorResponse,
    83: BluetoothGATTWriteResponse,
    84: BluetoothGATTNotifyResponse,
    85: BluetoothDevicePairingResponse,
    86: BluetoothDeviceUnpairingResponse,
    87: UnsubscribeBluetoothLEAdvertisementsRequest,
    88: BluetoothDeviceClearCacheResponse,
    89: SubscribeVoiceAssistantRequest,
    90: VoiceAssistantRequest,
    91: VoiceAssistantResponse,
    92: VoiceAssistantEventResponse,
}
