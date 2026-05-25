# ruff: noqa: F401, F403
from .api_pb2 import (  # type: ignore[attr-defined]
    BluetoothLERawAdvertisement,
    BluetoothLERawAdvertisementsResponse,
)
from .ble_defs import ESP_CONNECTION_ERROR_DESCRIPTION, BLEConnectionError
from .client import APIClient
from .connection import APIConnection, ConnectionParams
from .core import (
    ESPHOME_GATT_ERRORS,
    MESSAGE_TYPE_TO_PROTO,
    APIConnectionError,
    BadMACAddressAPIError,
    BadNameAPIError,
    BluetoothConnectionDroppedError,
    EncryptionHelloAPIError,
    EncryptionPlaintextAPIError,
    HandshakeAPIError,
    InvalidAuthAPIError,
    InvalidEncryptionKeyAPIError,
    ProtocolAPIError,
    RequiresEncryptionAPIError,
    ResolveAPIError,
    SocketAPIError,
    wifi_mac_to_bluetooth_mac,
)
from .log_parser import LogParser, parse_log_message
from .model import *
from .reconnect_logic import ReconnectLogic
