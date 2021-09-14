from .api_pb2 import (  # type: ignore
    BinarySensorStateResponse,
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
    ListEntitiesCameraResponse,
    ListEntitiesClimateResponse,
    ListEntitiesCoverResponse,
    ListEntitiesDoneResponse,
    ListEntitiesFanResponse,
    ListEntitiesLightResponse,
    ListEntitiesNumberResponse,
    ListEntitiesRequest,
    ListEntitiesSelectResponse,
    ListEntitiesSensorResponse,
    ListEntitiesServicesResponse,
    ListEntitiesSirenResponse,
    ListEntitiesSwitchResponse,
    ListEntitiesTextSensorResponse,
    NumberCommandRequest,
    NumberStateResponse,
    PingRequest,
    PingResponse,
    SelectCommandRequest,
    SelectStateResponse,
    SensorStateResponse,
    SirenCommandRequest,
    SirenStateResponse,
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


class HandshakeAPIError(APIConnectionError):
    pass


class InvalidEncryptionKeyAPIError(HandshakeAPIError):
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
}
