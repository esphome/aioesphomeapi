from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from google.protobuf import message

from .api_pb2 import (  # type: ignore
    BluetoothConnectionsFreeResponse,
    BluetoothGATTNotifyDataResponse,
    BluetoothLEAdvertisementResponse,
    BluetoothLERawAdvertisement,
    BluetoothLERawAdvertisementsResponse,
    CameraImageResponse,
    HomeassistantServiceResponse,
    SubscribeHomeAssistantStateResponse,
)
from .model import (
    BluetoothLEAdvertisement,
    CameraState,
    EntityState,
    HomeassistantServiceCall,
)
from .model_conversions import SUBSCRIBE_STATES_RESPONSE_TYPES


def on_state_msg(
    on_state: Callable[[EntityState], None],
    image_stream: dict[int, list[bytes]],
    msg: message.Message,
) -> None:
    """Handle a state message."""
    msg_type = type(msg)
    if cls := SUBSCRIBE_STATES_RESPONSE_TYPES.get(msg_type):
        on_state(cls.from_pb(msg))
    elif msg_type is CameraImageResponse:
        if TYPE_CHECKING:
            assert isinstance(msg, CameraImageResponse)
        msg_key = msg.key
        data_parts: list[bytes] | None = image_stream.get(msg_key)
        if not data_parts:
            data_parts = []
            image_stream[msg_key] = data_parts

        data_parts.append(msg.data)
        if msg.done:
            # Return CameraState with the merged data
            image_data = b"".join(data_parts)
            del image_stream[msg_key]
            on_state(CameraState(key=msg.key, data=image_data))  # type: ignore[call-arg]


def on_home_assistant_service_response(
    on_service_call: Callable[[HomeassistantServiceCall], None],
    msg: HomeassistantServiceResponse,
) -> None:
    on_service_call(HomeassistantServiceCall.from_pb(msg))


def on_bluetooth_le_advertising_response(
    on_bluetooth_le_advertisement: Callable[[BluetoothLEAdvertisement], None],
    msg: BluetoothLEAdvertisementResponse,
) -> None:
    on_bluetooth_le_advertisement(BluetoothLEAdvertisement.from_pb(msg))  # type: ignore[misc]


def on_ble_raw_advertisement_response(
    on_advertisements: Callable[[list[BluetoothLERawAdvertisement]], None],
    msg: BluetoothLERawAdvertisementsResponse,
) -> None:
    on_advertisements(msg.advertisements)


def on_bluetooth_connections_free_response(
    on_bluetooth_connections_free_update: Callable[[int, int], None],
    msg: BluetoothConnectionsFreeResponse,
) -> None:
    on_bluetooth_connections_free_update(msg.free, msg.limit)


def on_bluetooth_gatt_notify_data_response(
    address: int,
    handle: int,
    on_bluetooth_gatt_notify: Callable[[int, bytearray], None],
    msg: BluetoothGATTNotifyDataResponse,
) -> None:
    """Handle a BluetoothGATTNotifyDataResponse message."""
    if address == msg.address and handle == msg.handle:
        on_bluetooth_gatt_notify(handle, bytearray(msg.data))


def on_subscribe_home_assistant_state_response(
    on_state_sub: Callable[[str, str | None], None],
    msg: SubscribeHomeAssistantStateResponse,
) -> None:
    on_state_sub(msg.entity_id, msg.attribute)
