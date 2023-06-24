from __future__ import annotations

from enum import IntEnum


class BLEConnectionError(IntEnum):
    """BLE Connection Error."""

    ESP_GATT_CONN_UNKNOWN = 0
    ESP_GATT_CONN_L2C_FAILURE = 1
    ESP_GATT_CONN_TIMEOUT = 0x08
    ESP_GATT_CONN_TERMINATE_PEER_USER = 0x13
    ESP_GATT_CONN_TERMINATE_LOCAL_HOST = 0x16
    ESP_GATT_CONN_FAIL_ESTABLISH = 0x3E
    ESP_GATT_CONN_LMP_TIMEOUT = 0x22
    ESP_GATT_ERROR = 0x85
    ESP_GATT_CONN_CONN_CANCEL = 0x0100
    ESP_GATT_CONN_NONE = 0x0101


ESP_CONNECTION_ERROR_DESCRIPTION = {
    BLEConnectionError.ESP_GATT_CONN_UNKNOWN: "Connection failed for unknown reason",
    BLEConnectionError.ESP_GATT_CONN_L2C_FAILURE: "Connection failed due to L2CAP failure",
    BLEConnectionError.ESP_GATT_CONN_TIMEOUT: "Connection failed due to timeout",
    BLEConnectionError.ESP_GATT_CONN_TERMINATE_PEER_USER: "Connection terminated by peer user",
    BLEConnectionError.ESP_GATT_CONN_TERMINATE_LOCAL_HOST: "Connection terminated by local host",
    BLEConnectionError.ESP_GATT_CONN_FAIL_ESTABLISH: "Connection failed to establish",
    BLEConnectionError.ESP_GATT_CONN_LMP_TIMEOUT: "Connection failed due to LMP response timeout",
    BLEConnectionError.ESP_GATT_ERROR: "Connection failed due to GATT operation error",
    BLEConnectionError.ESP_GATT_CONN_CONN_CANCEL: "Connection cancelled",
    BLEConnectionError.ESP_GATT_CONN_NONE: "No connection to cancel",
}
