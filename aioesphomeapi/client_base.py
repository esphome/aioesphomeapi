# pylint: disable=unidiomatic-typecheck
from __future__ import annotations

import asyncio
from collections.abc import Coroutine
import logging
from typing import TYPE_CHECKING, Any, Callable

from google.protobuf import message

from ._frame_helper.base import APIFrameHelper  # noqa: F401
from ._frame_helper.noise import APINoiseFrameHelper  # noqa: F401
from ._frame_helper.plain_text import APIPlaintextFrameHelper  # noqa: F401
from .api_pb2 import (  # type: ignore
    BluetoothConnectionsFreeResponse,
    BluetoothDeviceConnectionResponse,
    BluetoothGATTErrorResponse,
    BluetoothGATTGetServicesDoneResponse,
    BluetoothGATTGetServicesResponse,
    BluetoothGATTNotifyDataResponse,
    BluetoothGATTNotifyResponse,
    BluetoothGATTReadResponse,
    BluetoothGATTWriteResponse,
    BluetoothLEAdvertisementResponse,
    BluetoothScannerStateResponse,
    CameraImageResponse,
    HomeassistantServiceResponse,
    SubscribeHomeAssistantStateResponse,
)
from .connection import ConnectionParams
from .core import APIConnectionError
from .model import (
    APIVersion,
    BluetoothLEAdvertisement,
    BluetoothScannerStateResponse as BluetoothScannerStateResponseModel,
    CameraState,
    EntityState,
    HomeassistantServiceCall,
)
from .model_conversions import SUBSCRIBE_STATES_RESPONSE_TYPES
from .util import build_log_name, create_eager_task
from .zeroconf import ZeroconfInstanceType, ZeroconfManager

if TYPE_CHECKING:
    from .connection import APIConnection

_LOGGER = logging.getLogger(__name__)

# We send a ping every 20 seconds, and the timeout ratio is 4.5x the
# ping interval. This means that if we don't receive a ping for 90.0
# seconds, we'll consider the connection dead and reconnect.
#
# This was chosen because the 20s is around the expected time for a
# device to reboot and reconnect to wifi, and 90 seconds is the absolute
# maximum time a device can take to respond when its behind + the WiFi
# connection is poor.
KEEP_ALIVE_FREQUENCY = 20.0


def on_state_msg(
    on_state: Callable[[EntityState], None],
    image_stream: dict[int, list[bytes]],
    msg: message.Message,
) -> None:
    """Handle a state message."""
    msg_type = type(msg)
    if (cls := SUBSCRIBE_STATES_RESPONSE_TYPES.get(msg_type)) is not None:
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
            on_state(CameraState(key=msg.key, data=image_data, device_id=msg.device_id))  # type: ignore[call-arg]


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


def on_bluetooth_connections_free_response(
    on_bluetooth_connections_free_update: Callable[[int, int, list[int]], None],
    msg: BluetoothConnectionsFreeResponse,
) -> None:
    on_bluetooth_connections_free_update(msg.free, msg.limit, list(msg.allocated))


def on_bluetooth_gatt_notify_data_response(
    address: int,
    handle: int,
    on_bluetooth_gatt_notify: Callable[[int, bytearray], None],
    msg: BluetoothGATTNotifyDataResponse,
) -> None:
    """Handle a BluetoothGATTNotifyDataResponse message."""
    if address == msg.address and handle == msg.handle:
        try:
            on_bluetooth_gatt_notify(handle, bytearray(msg.data))
        except Exception:
            _LOGGER.exception(
                "Unexpected error in Bluetooth GATT notify callback for address %s, handle %s",
                address,
                handle,
            )


def on_bluetooth_scanner_state_response(
    on_bluetooth_scanner_state: Callable[[BluetoothScannerStateResponseModel], None],
    msg: BluetoothScannerStateResponse,
) -> None:
    on_bluetooth_scanner_state(BluetoothScannerStateResponseModel.from_pb(msg))


def on_subscribe_home_assistant_state_response(
    on_state_sub: Callable[[str, str | None], None],
    on_state_request: Callable[[str, str | None], None] | None,
    msg: SubscribeHomeAssistantStateResponse,
) -> None:
    if on_state_request and msg.once:
        on_state_request(msg.entity_id, msg.attribute)
    else:
        on_state_sub(msg.entity_id, msg.attribute)


def on_bluetooth_device_connection_response(
    connect_future: asyncio.Future[None],
    address: int,
    on_bluetooth_connection_state: Callable[[bool, int, int], None],
    msg: BluetoothDeviceConnectionResponse,
) -> None:
    """Handle a BluetoothDeviceConnectionResponse message.""" ""
    if address == msg.address:
        on_bluetooth_connection_state(msg.connected, msg.mtu, msg.error)
        # Resolve on ANY connection state since we do not want
        # to wait the whole timeout if the device disconnects
        # or we get an error.
        if not connect_future.done():
            connect_future.set_result(None)


def on_bluetooth_handle_message(
    address: int,
    handle: int,
    msg: (
        BluetoothGATTErrorResponse
        | BluetoothGATTNotifyResponse
        | BluetoothGATTReadResponse
        | BluetoothGATTWriteResponse
        | BluetoothDeviceConnectionResponse
    ),
) -> bool:
    """Filter a Bluetooth message for an address and handle."""
    if type(msg) is BluetoothDeviceConnectionResponse:
        return bool(msg.address == address)
    return bool(msg.address == address and msg.handle == handle)


def on_bluetooth_message_types(
    address: int,
    msg_types: tuple[type[message.Message], ...],
    msg: (
        BluetoothGATTErrorResponse
        | BluetoothGATTNotifyResponse
        | BluetoothGATTReadResponse
        | BluetoothGATTWriteResponse
        | BluetoothDeviceConnectionResponse
        | BluetoothGATTGetServicesResponse
        | BluetoothGATTGetServicesDoneResponse
        | BluetoothGATTErrorResponse
    ),
) -> bool:
    """Filter Bluetooth messages of a specific type and address."""
    return type(msg) in msg_types and bool(msg.address == address)


str_ = str


def _stringify_or_none(value: str_ | None) -> str | None:
    """Convert a string like object to a str or None.

    The noise_psk is sometimes passed into
    the client as an Estr, but we want to pass it
    to the API as a string or None.
    """
    return None if value is None else str(value)


class APIClientBase:
    """Base client for ESPHome API clients."""

    __slots__ = (
        "_background_tasks",
        "_connection",
        "_debug_enabled",
        "_loop",
        "_params",
        "cached_name",
        "log_name",
    )

    def __init__(
        self,
        address: str_,  # allow subclass str
        port: int,
        password: str_ | None,
        *,
        client_info: str_ = "aioesphomeapi",
        keepalive: float = KEEP_ALIVE_FREQUENCY,
        zeroconf_instance: ZeroconfInstanceType | None = None,
        noise_psk: str_ | None = None,
        expected_name: str_ | None = None,
        addresses: list[str_] | None = None,
        expected_mac: str_ | None = None,
    ) -> None:
        """Create a client, this object is shared across sessions.

        :param address: The address to connect to; for example an IP address
          or .local name for mDNS lookup.
        :param port: The port to connect to
        :param password: Optional password to send to the device for authentication
        :param client_info: User Agent string to send.
        :param keepalive: The keepalive time in seconds (ping interval) for detecting stale connections.
            Every keepalive seconds a ping is sent, if no pong is received the connection is closed.
        :param zeroconf_instance: Pass a zeroconf instance to use if an mDNS lookup is necessary.
        :param noise_psk: Encryption preshared key for noise transport encrypted sessions.
        :param expected_name: Require the devices name to match the given expected name.
            Can be used to prevent accidentally connecting to a different device if
            IP passed as address but DHCP reassigned IP.
        :param addresses: Optional list of IP addresses to connect to which takes
            precedence over the address parameter. This is most commonly used when
            the device has dual stack IPv4 and IPv6 addresses and you do not know
            which one to connect to.
        :param expected_mac: Optional MAC address to check against the device.
            The format should be lower case without : or - separators.
            Example: 00:aa:22:33:44:55 -> 00aa22334455
        """
        self._debug_enabled = _LOGGER.isEnabledFor(logging.DEBUG)
        self._params = ConnectionParams(
            addresses=addresses if addresses else [str(address)],
            port=port,
            password=password,
            client_info=client_info,
            keepalive=keepalive,
            zeroconf_manager=ZeroconfManager(zeroconf_instance),
            # treat empty '' psk string as missing (like password)
            noise_psk=_stringify_or_none(noise_psk) or None,
            expected_name=_stringify_or_none(expected_name) or None,
            expected_mac=_stringify_or_none(expected_mac) or None,
        )
        self._connection: APIConnection | None = None
        self.cached_name: str | None = None
        self._background_tasks: set[asyncio.Task[Any]] = set()
        self._loop = asyncio.get_running_loop()
        self._set_log_name()

    def set_debug(self, enabled: bool) -> None:
        """Enable debug logging."""
        self._debug_enabled = enabled
        if self._connection is not None:
            self._connection.set_debug(enabled)

    @property
    def zeroconf_manager(self) -> ZeroconfManager:
        return self._params.zeroconf_manager

    @property
    def expected_name(self) -> str | None:
        return self._params.expected_name

    @expected_name.setter
    def expected_name(self, value: str | None) -> None:
        self._params.expected_name = value

    @property
    def address(self) -> str:
        return self._params.addresses[0]

    @property
    def api_version(self) -> APIVersion | None:
        if self._connection is None:
            return None
        return self._connection.api_version

    def _set_log_name(self) -> None:
        """Set the log name of the device."""
        connected_address: str | None = None
        if self._connection is not None and self._connection.connected_address:
            connected_address = self._connection.connected_address
        self.log_name = build_log_name(
            self.cached_name,
            self._params.addresses,
            connected_address,
        )
        if self._connection is not None:
            self._connection.set_log_name(self.log_name)

    def _set_name_from_device(self, name: str_) -> None:
        """Set the name from a DeviceInfo message."""
        self.cached_name = str(name)  # May be Estr from esphome
        self._set_log_name()

    def set_cached_name_if_unset(self, name: str_) -> None:
        """Set the cached name of the device if not set."""
        if not self.cached_name:
            self._set_name_from_device(name)

    def _create_background_task(self, coro: Coroutine[Any, Any, None]) -> None:
        """Create a background task and add it to the background tasks set."""
        task = create_eager_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _get_connection(self) -> APIConnection:
        if self._connection is None:
            raise APIConnectionError(f"Not connected to {self.log_name}!")
        if not self._connection.is_connected:
            raise APIConnectionError(
                f"Authenticated connection not ready yet for {self.log_name}; "
                f"current state is {self._connection.connection_state}!"
            )
        return self._connection
