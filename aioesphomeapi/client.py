# pylint: disable=unidiomatic-typecheck
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Coroutine
from functools import partial
from typing import TYPE_CHECKING, Any, Callable, Union

from google.protobuf import message

from .api_pb2 import (  # type: ignore
    AlarmControlPanelCommandRequest,
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
    BluetoothLERawAdvertisementsResponse,
    ButtonCommandRequest,
    CameraImageRequest,
    CameraImageResponse,
    ClimateCommandRequest,
    CoverCommandRequest,
    DeviceInfoRequest,
    DeviceInfoResponse,
    ExecuteServiceArgument,
    ExecuteServiceRequest,
    FanCommandRequest,
    HomeassistantServiceResponse,
    HomeAssistantStateResponse,
    LightCommandRequest,
    ListEntitiesDoneResponse,
    ListEntitiesRequest,
    ListEntitiesServicesResponse,
    LockCommandRequest,
    MediaPlayerCommandRequest,
    NumberCommandRequest,
    SelectCommandRequest,
    SirenCommandRequest,
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
    TextCommandRequest,
    UnsubscribeBluetoothLEAdvertisementsRequest,
    VoiceAssistantEventData,
    VoiceAssistantEventResponse,
    VoiceAssistantRequest,
    VoiceAssistantResponse,
)
from .client_callbacks import (
    on_bluetooth_connections_free_response,
    on_bluetooth_device_connection_response,
    on_bluetooth_gatt_notify_data_response,
    on_bluetooth_handle_message,
    on_bluetooth_le_advertising_response,
    on_bluetooth_message_types,
    on_home_assistant_service_response,
    on_state_msg,
    on_subscribe_home_assistant_state_response,
)
from .connection import APIConnection, ConnectionParams, handle_timeout
from .core import (
    APIConnectionError,
    BluetoothConnectionDroppedError,
    BluetoothGATTAPIError,
    TimeoutAPIError,
    to_human_readable_address,
    to_human_readable_gatt_error,
)
from .model import (
    AlarmControlPanelCommand,
    APIVersion,
    BluetoothDeviceClearCache,
    BluetoothDevicePairing,
    BluetoothDeviceRequestType,
    BluetoothDeviceUnpairing,
    BluetoothGATTError,
    BluetoothGATTServices,
    BluetoothLEAdvertisement,
    BluetoothProxyFeature,
    BluetoothProxySubscriptionFlag,
    ClimateFanMode,
    ClimateMode,
    ClimatePreset,
    ClimateSwingMode,
    DeviceInfo,
    EntityInfo,
    EntityState,
    ESPHomeBluetoothGATTServices,
    FanDirection,
    FanSpeed,
    HomeassistantServiceCall,
    LegacyCoverCommand,
    LockCommand,
    LogLevel,
    MediaPlayerCommand,
    UserService,
    UserServiceArgType,
)
from .model import VoiceAssistantAudioSettings as VoiceAssistantAudioSettingsModel
from .model import (
    VoiceAssistantCommand,
    VoiceAssistantEventType,
    message_types_to_names,
)
from .model_conversions import (
    LIST_ENTITIES_SERVICES_RESPONSE_TYPES,
    SUBSCRIBE_STATES_RESPONSE_TYPES,
)
from .util import build_log_name
from .zeroconf import ZeroconfInstanceType, ZeroconfManager

_LOGGER = logging.getLogger(__name__)

DEFAULT_BLE_TIMEOUT = 30.0
DEFAULT_BLE_DISCONNECT_TIMEOUT = 20.0

# We send a ping every 20 seconds, and the timeout ratio is 4.5x the
# ping interval. This means that if we don't receive a ping for 90.0
# seconds, we'll consider the connection dead and reconnect.
#
# This was chosen because the 20s is around the expected time for a
# device to reboot and reconnect to wifi, and 90 seconds is the absolute
# maximum time a device can take to respond when its behind + the WiFi
# connection is poor.
KEEP_ALIVE_FREQUENCY = 20.0


SUBSCRIBE_STATES_MSG_TYPES = (*SUBSCRIBE_STATES_RESPONSE_TYPES, CameraImageResponse)

LIST_ENTITIES_MSG_TYPES = (
    ListEntitiesDoneResponse,
    *LIST_ENTITIES_SERVICES_RESPONSE_TYPES,
)

USER_SERVICE_MAP_ARRAY = {
    UserServiceArgType.BOOL_ARRAY: "bool_array",
    UserServiceArgType.INT_ARRAY: "int_array",
    UserServiceArgType.FLOAT_ARRAY: "float_array",
    UserServiceArgType.STRING_ARRAY: "string_array",
}
USER_SERVICE_MAP_SINGLE = {
    # Int is a special case because it is handled
    # differently depending on the APIVersion
    UserServiceArgType.BOOL: "bool_",
    UserServiceArgType.FLOAT: "float_",
    UserServiceArgType.STRING: "string_",
}


ExecuteServiceDataType = dict[
    str, Union[bool, int, float, str, list[bool], list[int], list[float], list[str]]
]


def _stringify_or_none(value: str | None) -> str | None:
    """Convert a string like object to a str or None.

    The noise_psk is sometimes passed into
    the client as an Estr, but we want to pass it
    to the API as a string or None.
    """
    return None if value is None else str(value)


# pylint: disable=too-many-public-methods
class APIClient:
    """The ESPHome API client.

    This class is the main entrypoint for interacting with the API.

    It is recommended to use this class in combination with the
    ReconnectLogic class to automatically reconnect to the device
    if the connection is lost.
    """

    __slots__ = (
        "_debug_enabled",
        "_params",
        "_connection",
        "cached_name",
        "_background_tasks",
        "_loop",
        "log_name",
    )

    def __init__(
        self,
        address: str,
        port: int,
        password: str | None,
        *,
        client_info: str = "aioesphomeapi",
        keepalive: float = KEEP_ALIVE_FREQUENCY,
        zeroconf_instance: ZeroconfInstanceType | None = None,
        noise_psk: str | None = None,
        expected_name: str | None = None,
        addresses: list[str] | None = None,
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
        )
        self._connection: APIConnection | None = None
        self.cached_name: str | None = None
        self._background_tasks: set[asyncio.Task[Any]] = set()
        self._loop = asyncio.get_event_loop()
        self._set_log_name()

    def set_debug(self, enabled: bool) -> None:
        """Enable debug logging."""
        self._debug_enabled = enabled
        if self._connection:
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

    def _set_log_name(self) -> None:
        """Set the log name of the device."""
        connected_address: str | None = None
        if self._connection and self._connection.connected_address:
            connected_address = self._connection.connected_address
        self.log_name = build_log_name(
            self.cached_name,
            self._params.addresses,
            connected_address,
        )
        if self._connection:
            self._connection.set_log_name(self.log_name)

    def set_cached_name_if_unset(self, name: str) -> None:
        """Set the cached name of the device if not set."""
        if not self.cached_name:
            self.cached_name = name
            self._set_log_name()

    async def connect(
        self,
        on_stop: Callable[[bool], Coroutine[Any, Any, None]] | None = None,
        login: bool = False,
    ) -> None:
        """Connect to the device."""
        await self.start_connection(on_stop)
        await self.finish_connection(login)

    def _on_stop(
        self,
        on_stop: Callable[[bool], Coroutine[Any, Any, None]] | None,
        expected_disconnect: bool,
    ) -> None:
        # Hook into on_stop handler to clear connection when stopped
        self._connection = None
        if on_stop:
            self._create_background_task(on_stop(expected_disconnect))

    async def start_connection(
        self,
        on_stop: Callable[[bool], Awaitable[None]] | None = None,
    ) -> None:
        """Start connecting to the device."""
        if self._connection is not None:
            raise APIConnectionError(f"Already connected to {self.log_name}!")
        self._connection = APIConnection(
            self._params,
            partial(self._on_stop, on_stop),
            self._debug_enabled,
            self.log_name,
        )
        await self._execute_connection_coro(self._connection.start_connection())
        # If we connected, we should set the log name now
        if self._connection.connected_address:
            self._set_log_name()

    async def finish_connection(
        self,
        login: bool = False,
    ) -> None:
        """Finish connecting to the device."""
        if TYPE_CHECKING:
            assert self._connection is not None
        await self._execute_connection_coro(
            self._connection.finish_connection(login=login)
        )
        if received_name := self._connection.received_name:
            self._set_name_from_device(received_name)

    async def _execute_connection_coro(self, coro: Awaitable[None]) -> None:
        """Execute a coroutine and reset the _connection if it fails."""
        try:
            await coro
        except (Exception, asyncio.CancelledError):  # pylint: disable=broad-except
            self._connection = None
            raise

    async def disconnect(self, force: bool = False) -> None:
        if self._connection is None:
            return
        if force:
            self._connection.force_disconnect()
        else:
            await self._connection.disconnect()

    def _get_connection(self) -> APIConnection:
        connection = self._connection
        if not connection:
            raise APIConnectionError(f"Not connected to {self.log_name}!")
        if not connection.is_connected:
            raise APIConnectionError(
                f"Authenticated connection not ready yet for {self.log_name}; "
                f"current state is {connection.connection_state}!"
            )
        return connection

    async def device_info(self) -> DeviceInfo:
        resp = await self._get_connection().send_message_await_response(
            DeviceInfoRequest(), DeviceInfoResponse
        )
        info = DeviceInfo.from_pb(resp)
        self._set_name_from_device(info.name)
        return info

    def _set_name_from_device(self, name: str) -> None:
        """Set the name from a DeviceInfo message."""
        self.cached_name = name
        self._set_log_name()

    async def list_entities_services(
        self,
    ) -> tuple[list[EntityInfo], list[UserService]]:
        msgs = await self._get_connection().send_messages_await_response_complex(
            (ListEntitiesRequest(),),
            lambda msg: type(msg) is not ListEntitiesDoneResponse,
            lambda msg: type(msg) is ListEntitiesDoneResponse,
            LIST_ENTITIES_MSG_TYPES,
            60,
        )
        entities: list[EntityInfo] = []
        services: list[UserService] = []
        response_types = LIST_ENTITIES_SERVICES_RESPONSE_TYPES
        for msg in msgs:
            msg_type = type(msg)
            if msg_type is ListEntitiesServicesResponse:
                services.append(UserService.from_pb(msg))
                continue
            if cls := response_types[msg_type]:
                entities.append(cls.from_pb(msg))
        return entities, services

    async def subscribe_states(self, on_state: Callable[[EntityState], None]) -> None:
        """Subscribe to state updates."""
        self._get_connection().send_message_callback_response(
            SubscribeStatesRequest(),
            partial(on_state_msg, on_state, {}),
            SUBSCRIBE_STATES_MSG_TYPES,
        )

    async def subscribe_logs(
        self,
        on_log: Callable[[SubscribeLogsResponse], None],
        log_level: LogLevel | None = None,
        dump_config: bool | None = None,
    ) -> None:
        req = SubscribeLogsRequest()
        if log_level is not None:
            req.level = log_level
        if dump_config is not None:
            req.dump_config = dump_config
        self._get_connection().send_message_callback_response(
            req, on_log, (SubscribeLogsResponse,)
        )

    async def subscribe_service_calls(
        self, on_service_call: Callable[[HomeassistantServiceCall], None]
    ) -> None:
        self._get_connection().send_message_callback_response(
            SubscribeHomeassistantServicesRequest(),
            partial(on_home_assistant_service_response, on_service_call),
            (HomeassistantServiceResponse,),
        )

    async def _send_bluetooth_message_await_response(
        self,
        address: int,
        handle: int,
        request: message.Message,
        response_type: (
            type[BluetoothGATTNotifyResponse]
            | type[BluetoothGATTReadResponse]
            | type[BluetoothGATTWriteResponse]
        ),
        timeout: float = 10.0,
    ) -> message.Message:
        message_filter = partial(on_bluetooth_handle_message, address, handle)
        msg_types = (response_type, BluetoothGATTErrorResponse)
        [resp] = await self._get_connection().send_messages_await_response_complex(
            (request,),
            message_filter,
            message_filter,
            (*msg_types, BluetoothDeviceConnectionResponse),
            timeout,
        )

        if type(resp) is BluetoothGATTErrorResponse:
            raise BluetoothGATTAPIError(BluetoothGATTError.from_pb(resp))

        self._raise_for_ble_connection_change(address, resp, msg_types)

        return resp

    def _unsub_bluetooth_advertisements(
        self, unsub_callback: Callable[[], None]
    ) -> None:
        """Unsubscribe Bluetooth advertisements if connected."""
        if self._connection is not None:
            unsub_callback()
            self._connection.send_message(UnsubscribeBluetoothLEAdvertisementsRequest())

    async def subscribe_bluetooth_le_advertisements(
        self, on_bluetooth_le_advertisement: Callable[[BluetoothLEAdvertisement], None]
    ) -> Callable[[], None]:
        unsub_callback = self._get_connection().send_message_callback_response(
            SubscribeBluetoothLEAdvertisementsRequest(flags=0),
            partial(
                on_bluetooth_le_advertising_response,
                on_bluetooth_le_advertisement,
            ),
            (BluetoothLEAdvertisementResponse,),
        )
        return partial(self._unsub_bluetooth_advertisements, unsub_callback)

    async def subscribe_bluetooth_le_raw_advertisements(
        self, on_advertisements: Callable[[BluetoothLERawAdvertisementsResponse], None]
    ) -> Callable[[], None]:
        unsub_callback = self._get_connection().send_message_callback_response(
            SubscribeBluetoothLEAdvertisementsRequest(
                flags=BluetoothProxySubscriptionFlag.RAW_ADVERTISEMENTS
            ),
            on_advertisements,
            (BluetoothLERawAdvertisementsResponse,),
        )
        return partial(self._unsub_bluetooth_advertisements, unsub_callback)

    async def subscribe_bluetooth_connections_free(
        self, on_bluetooth_connections_free_update: Callable[[int, int], None]
    ) -> Callable[[], None]:
        return self._get_connection().send_message_callback_response(
            SubscribeBluetoothConnectionsFreeRequest(),
            partial(
                on_bluetooth_connections_free_response,
                on_bluetooth_connections_free_update,
            ),
            (BluetoothConnectionsFreeResponse,),
        )

    async def bluetooth_device_connect(  # pylint: disable=too-many-locals, too-many-branches
        self,
        address: int,
        on_bluetooth_connection_state: Callable[[bool, int, int], None],
        timeout: float = DEFAULT_BLE_TIMEOUT,
        disconnect_timeout: float = DEFAULT_BLE_DISCONNECT_TIMEOUT,
        feature_flags: int = 0,
        has_cache: bool = False,
        address_type: int | None = None,
    ) -> Callable[[], None]:
        connect_future: asyncio.Future[None] = self._loop.create_future()

        if has_cache:
            # REMOTE_CACHING feature with cache: requestor has services and mtu cached
            request_type = BluetoothDeviceRequestType.CONNECT_V3_WITH_CACHE
        elif feature_flags & BluetoothProxyFeature.REMOTE_CACHING:
            # REMOTE_CACHING feature without cache: esp will wipe the service list after sending to save memory
            request_type = BluetoothDeviceRequestType.CONNECT_V3_WITHOUT_CACHE
        else:
            # Device does not support REMOTE_CACHING feature: esp will hold the service list in memory for the duration
            # of the connection. This can crash the esp if the service list is too large.
            request_type = BluetoothDeviceRequestType.CONNECT

        if self._debug_enabled:
            _LOGGER.debug("%s: Using connection version %s", address, request_type)

        unsub = self._get_connection().send_message_callback_response(
            BluetoothDeviceRequest(
                address=address,
                request_type=request_type,
                has_address_type=address_type is not None,
                address_type=address_type or 0,
            ),
            partial(
                on_bluetooth_device_connection_response,
                connect_future,
                address,
                on_bluetooth_connection_state,
            ),
            (BluetoothDeviceConnectionResponse,),
        )

        loop = self._loop
        timeout_handle = loop.call_at(
            loop.time() + timeout, handle_timeout, connect_future
        )
        timeout_expired = False
        connect_ok = False
        try:
            await connect_future
            connect_ok = True
        except asyncio.TimeoutError as err:
            # If the timeout expires, make sure
            # to unsub before calling _bluetooth_device_disconnect_guard_timeout
            # so that the disconnect message is not propagated back to the caller
            # since we are going to raise a TimeoutAPIError.
            unsub()
            timeout_expired = True
            # Disconnect before raising the exception to ensure
            # the slot is recovered before the timeout is raised
            # to avoid race were we run out even though we have a slot.
            addr = to_human_readable_address(address)
            if self._debug_enabled:
                _LOGGER.debug("%s: Connecting timed out, waiting for disconnect", addr)
            disconnect_timed_out = (
                not await self._bluetooth_device_disconnect_guard_timeout(
                    address, disconnect_timeout
                )
            )
            raise TimeoutAPIError(
                f"Timeout waiting for connect response while connecting to {addr} "
                f"after {timeout}s, disconnect timed out: {disconnect_timed_out}, "
                f" after {disconnect_timeout}s"
            ) from err
        finally:
            if not connect_ok and not timeout_expired:
                unsub()
            if not timeout_expired:
                timeout_handle.cancel()

        return unsub

    async def _bluetooth_device_disconnect_guard_timeout(
        self, address: int, timeout: float
    ) -> bool:
        """Disconnect from a Bluetooth device and guard against timeout.

        Return true if the disconnect was successful, false if it timed out.
        """
        try:
            await self.bluetooth_device_disconnect(address, timeout=timeout)
        except TimeoutAPIError:
            if self._debug_enabled:
                _LOGGER.debug(
                    "%s: Disconnect timed out: %s",
                    to_human_readable_address(address),
                    timeout,
                )
            return False
        return True

    async def bluetooth_device_pair(
        self, address: int, timeout: float = DEFAULT_BLE_TIMEOUT
    ) -> BluetoothDevicePairing:
        return BluetoothDevicePairing.from_pb(
            await self._bluetooth_device_request_watch_connection(
                address,
                BluetoothDeviceRequestType.PAIR,
                (BluetoothDevicePairingResponse,),
                timeout,
            )
        )

    async def bluetooth_device_unpair(
        self, address: int, timeout: float = DEFAULT_BLE_TIMEOUT
    ) -> BluetoothDeviceUnpairing:
        return BluetoothDeviceUnpairing.from_pb(
            await self._bluetooth_device_request_watch_connection(
                address,
                BluetoothDeviceRequestType.UNPAIR,
                (BluetoothDeviceUnpairingResponse,),
                timeout,
            )
        )

    async def bluetooth_device_clear_cache(
        self, address: int, timeout: float = DEFAULT_BLE_TIMEOUT
    ) -> BluetoothDeviceClearCache:
        return BluetoothDeviceClearCache.from_pb(
            await self._bluetooth_device_request_watch_connection(
                address,
                BluetoothDeviceRequestType.CLEAR_CACHE,
                (BluetoothDeviceClearCacheResponse,),
                timeout,
            )
        )

    async def bluetooth_device_disconnect(
        self, address: int, timeout: float = DEFAULT_BLE_DISCONNECT_TIMEOUT
    ) -> None:
        """Disconnect from a Bluetooth device."""
        await self._bluetooth_device_request(
            address,
            BluetoothDeviceRequestType.DISCONNECT,
            lambda msg: msg.address == address and not msg.connected,
            (BluetoothDeviceConnectionResponse,),
            timeout,
        )

    async def _bluetooth_device_request_watch_connection(
        self,
        address: int,
        request_type: BluetoothDeviceRequestType,
        msg_types: tuple[type[message.Message], ...],
        timeout: float,
    ) -> message.Message:
        """Send a BluetoothDeviceRequest watch for the connection state to change."""
        types_with_response = (BluetoothDeviceConnectionResponse, *msg_types)
        response = await self._bluetooth_device_request(
            address,
            request_type,
            partial(on_bluetooth_message_types, address, types_with_response),
            types_with_response,
            timeout,
        )
        self._raise_for_ble_connection_change(address, response, msg_types)
        return response

    def _raise_for_ble_connection_change(
        self,
        address: int,
        response: BluetoothDeviceConnectionResponse,
        msg_types: tuple[type[message.Message], ...],
    ) -> None:
        """Raise an exception if the connection status changed."""
        if type(response) is not BluetoothDeviceConnectionResponse:
            return
        response_names = message_types_to_names(msg_types)
        human_readable_address = to_human_readable_address(address)
        raise BluetoothConnectionDroppedError(
            f"Peripheral {human_readable_address} changed connection status while waiting for "
            f"{response_names}: {to_human_readable_gatt_error(response.error)} "
            f"({response.error})"
        )

    async def _bluetooth_device_request(
        self,
        address: int,
        request_type: BluetoothDeviceRequestType,
        predicate_func: Callable[[BluetoothDeviceConnectionResponse], bool],
        msg_types: tuple[type[message.Message], ...],
        timeout: float,
    ) -> message.Message:
        """Send a BluetoothDeviceRequest and wait for a response."""
        req = BluetoothDeviceRequest(address=address, request_type=request_type)
        [response] = await self._get_connection().send_messages_await_response_complex(
            (req,),
            predicate_func,
            predicate_func,
            msg_types,
            timeout,
        )
        return response

    async def bluetooth_gatt_get_services(
        self, address: int
    ) -> ESPHomeBluetoothGATTServices:
        error_types = (BluetoothGATTErrorResponse, BluetoothDeviceConnectionResponse)
        append_types = (*error_types, BluetoothGATTGetServicesResponse)
        stop_types = (*error_types, BluetoothGATTGetServicesDoneResponse)
        msg_types = (
            BluetoothGATTGetServicesResponse,
            BluetoothGATTGetServicesDoneResponse,
            BluetoothGATTErrorResponse,
        )
        resp = await self._get_connection().send_messages_await_response_complex(
            (BluetoothGATTGetServicesRequest(address=address),),
            partial(on_bluetooth_message_types, address, append_types),
            partial(on_bluetooth_message_types, address, stop_types),
            (*msg_types, BluetoothDeviceConnectionResponse),
            DEFAULT_BLE_TIMEOUT,
        )
        services = []
        for msg in resp:
            self._raise_for_ble_connection_change(address, msg, msg_types)
            if type(msg) is BluetoothGATTErrorResponse:
                raise BluetoothGATTAPIError(BluetoothGATTError.from_pb(msg))
            services.extend(BluetoothGATTServices.from_pb(msg).services)

        return ESPHomeBluetoothGATTServices(address=address, services=services)  # type: ignore[call-arg]

    async def bluetooth_gatt_read(
        self,
        address: int,
        handle: int,
        timeout: float = DEFAULT_BLE_TIMEOUT,
    ) -> bytearray:
        return await self._bluetooth_gatt_read(
            BluetoothGATTReadRequest,
            address,
            handle,
            timeout,
        )

    async def bluetooth_gatt_read_descriptor(
        self,
        address: int,
        handle: int,
        timeout: float = DEFAULT_BLE_TIMEOUT,
    ) -> bytearray:
        """Read a GATT descriptor."""
        return await self._bluetooth_gatt_read(
            BluetoothGATTReadDescriptorRequest,
            address,
            handle,
            timeout,
        )

    async def _bluetooth_gatt_read(
        self,
        req_type: (
            type[BluetoothGATTReadDescriptorRequest] | type[BluetoothGATTReadRequest]
        ),
        address: int,
        handle: int,
        timeout: float,
    ) -> bytearray:
        """Perform a GATT read."""
        resp = await self._send_bluetooth_message_await_response(
            address,
            handle,
            req_type(address=address, handle=handle),
            BluetoothGATTReadResponse,
            timeout,
        )
        if TYPE_CHECKING:
            assert isinstance(resp, BluetoothGATTReadResponse)
        return bytearray(resp.data)

    async def bluetooth_gatt_write(
        self,
        address: int,
        handle: int,
        data: bytes,
        response: bool,
        timeout: float = DEFAULT_BLE_TIMEOUT,
    ) -> None:
        await self._bluetooth_gatt_write(
            address,
            handle,
            BluetoothGATTWriteRequest(response=response, data=data),
            timeout,
            response,
        )

    async def bluetooth_gatt_write_descriptor(
        self,
        address: int,
        handle: int,
        data: bytes,
        timeout: float = DEFAULT_BLE_TIMEOUT,
        wait_for_response: bool = True,
    ) -> None:
        await self._bluetooth_gatt_write(
            address,
            handle,
            BluetoothGATTWriteDescriptorRequest(data=data),
            timeout,
            wait_for_response,
        )

    async def _bluetooth_gatt_write(
        self,
        address: int,
        handle: int,
        req: BluetoothGATTWriteDescriptorRequest | BluetoothGATTWriteRequest,
        timeout: float,
        wait_for_response: bool,
    ) -> None:
        """Perform a GATT write to a char or descriptor."""
        req.address = address
        req.handle = handle
        if not wait_for_response:
            self._get_connection().send_message(req)
            return
        await self._send_bluetooth_message_await_response(
            address,
            handle,
            req,
            BluetoothGATTWriteResponse,
            timeout,
        )

    async def bluetooth_gatt_start_notify(
        self,
        address: int,
        handle: int,
        on_bluetooth_gatt_notify: Callable[[int, bytearray], None],
        timeout: float = 10.0,
    ) -> tuple[Callable[[], Coroutine[Any, Any, None]], Callable[[], None]]:
        """Start a notify session for a GATT characteristic.

        Returns two functions that can be used to stop the notify.

        The first function is a coroutine that can be awaited to stop the notify.

        The second function is a callback that can be called to remove the notify
        callbacks without stopping the notify session on the remote device, which
        should be used when the connection is lost.
        """
        remove_callback = self._get_connection().add_message_callback(
            partial(
                on_bluetooth_gatt_notify_data_response,
                address,
                handle,
                on_bluetooth_gatt_notify,
            ),
            (BluetoothGATTNotifyDataResponse,),
        )

        try:
            await self._send_bluetooth_message_await_response(
                address,
                handle,
                BluetoothGATTNotifyRequest(address=address, handle=handle, enable=True),
                BluetoothGATTNotifyResponse,
                timeout,
            )
        except Exception:
            remove_callback()
            raise

        async def stop_notify() -> None:
            if self._connection is None:
                return

            remove_callback()

            self._connection.send_message(
                BluetoothGATTNotifyRequest(address=address, handle=handle, enable=False)
            )

        return stop_notify, remove_callback

    async def subscribe_home_assistant_states(
        self, on_state_sub: Callable[[str, str | None], None]
    ) -> None:
        self._get_connection().send_message_callback_response(
            SubscribeHomeAssistantStatesRequest(),
            partial(on_subscribe_home_assistant_state_response, on_state_sub),
            (SubscribeHomeAssistantStateResponse,),
        )

    async def send_home_assistant_state(
        self, entity_id: str, attribute: str | None, state: str
    ) -> None:
        self._get_connection().send_message(
            HomeAssistantStateResponse(
                entity_id=entity_id,
                state=state,
                attribute=attribute,
            )
        )

    async def cover_command(
        self,
        key: int,
        position: float | None = None,
        tilt: float | None = None,
        stop: bool = False,
    ) -> None:
        req = CoverCommandRequest(key=key)
        apiv = self.api_version
        if TYPE_CHECKING:
            assert apiv is not None
        if apiv >= APIVersion(1, 1):
            if position is not None:
                req.has_position = True
                req.position = position
            if tilt is not None:
                req.has_tilt = True
                req.tilt = tilt
            if stop:
                req.stop = stop
        else:
            if stop:
                req.legacy_command = LegacyCoverCommand.STOP
                req.has_legacy_command = True
            elif position == 1.0:
                req.legacy_command = LegacyCoverCommand.OPEN
                req.has_legacy_command = True
            elif position == 0.0:
                req.legacy_command = LegacyCoverCommand.CLOSE
                req.has_legacy_command = True
        self._get_connection().send_message(req)

    async def fan_command(
        self,
        key: int,
        state: bool | None = None,
        speed: FanSpeed | None = None,
        speed_level: int | None = None,
        oscillating: bool | None = None,
        direction: FanDirection | None = None,
        preset_mode: str | None = None,
    ) -> None:
        req = FanCommandRequest(key=key)
        if state is not None:
            req.has_state = True
            req.state = state
        if speed is not None:
            req.has_speed = True
            req.speed = speed
        if speed_level is not None:
            req.has_speed_level = True
            req.speed_level = speed_level
        if oscillating is not None:
            req.has_oscillating = True
            req.oscillating = oscillating
        if direction is not None:
            req.has_direction = True
            req.direction = direction
        if preset_mode is not None:
            req.has_preset_mode = True
            req.preset_mode = preset_mode
        self._get_connection().send_message(req)

    async def light_command(  # pylint: disable=too-many-branches
        self,
        key: int,
        state: bool | None = None,
        brightness: float | None = None,
        color_mode: int | None = None,
        color_brightness: float | None = None,
        rgb: tuple[float, float, float] | None = None,
        white: float | None = None,
        color_temperature: float | None = None,
        cold_white: float | None = None,
        warm_white: float | None = None,
        transition_length: float | None = None,
        flash_length: float | None = None,
        effect: str | None = None,
    ) -> None:
        req = LightCommandRequest(key=key)
        if state is not None:
            req.has_state = True
            req.state = state
        if brightness is not None:
            req.has_brightness = True
            req.brightness = brightness
        if color_mode is not None:
            req.has_color_mode = True
            req.color_mode = color_mode
        if color_brightness is not None:
            req.has_color_brightness = True
            req.color_brightness = color_brightness
        if rgb is not None:
            req.has_rgb = True
            req.red = rgb[0]
            req.green = rgb[1]
            req.blue = rgb[2]
        if white is not None:
            req.has_white = True
            req.white = white
        if color_temperature is not None:
            req.has_color_temperature = True
            req.color_temperature = color_temperature
        if cold_white is not None:
            req.has_cold_white = True
            req.cold_white = cold_white
        if warm_white is not None:
            req.has_warm_white = True
            req.warm_white = warm_white
        if transition_length is not None:
            req.has_transition_length = True
            req.transition_length = int(round(transition_length * 1000))
        if flash_length is not None:
            req.has_flash_length = True
            req.flash_length = int(round(flash_length * 1000))
        if effect is not None:
            req.has_effect = True
            req.effect = effect
        self._get_connection().send_message(req)

    async def switch_command(self, key: int, state: bool) -> None:
        self._get_connection().send_message(SwitchCommandRequest(key=key, state=state))

    async def climate_command(  # pylint: disable=too-many-branches
        self,
        key: int,
        mode: ClimateMode | None = None,
        target_temperature: float | None = None,
        target_temperature_low: float | None = None,
        target_temperature_high: float | None = None,
        fan_mode: ClimateFanMode | None = None,
        swing_mode: ClimateSwingMode | None = None,
        custom_fan_mode: str | None = None,
        preset: ClimatePreset | None = None,
        custom_preset: str | None = None,
        target_humidity: float | None = None,
    ) -> None:
        req = ClimateCommandRequest(key=key)
        if mode is not None:
            req.has_mode = True
            req.mode = mode
        if target_temperature is not None:
            req.has_target_temperature = True
            req.target_temperature = target_temperature
        if target_temperature_low is not None:
            req.has_target_temperature_low = True
            req.target_temperature_low = target_temperature_low
        if target_temperature_high is not None:
            req.has_target_temperature_high = True
            req.target_temperature_high = target_temperature_high
        if fan_mode is not None:
            req.has_fan_mode = True
            req.fan_mode = fan_mode
        if swing_mode is not None:
            req.has_swing_mode = True
            req.swing_mode = swing_mode
        if custom_fan_mode is not None:
            req.has_custom_fan_mode = True
            req.custom_fan_mode = custom_fan_mode
        if preset is not None:
            apiv = self.api_version
            if TYPE_CHECKING:
                assert apiv is not None
            if apiv < APIVersion(1, 5):
                req.has_legacy_away = True
                req.legacy_away = preset == ClimatePreset.AWAY
            else:
                req.has_preset = True
                req.preset = preset
        if custom_preset is not None:
            req.has_custom_preset = True
            req.custom_preset = custom_preset
        if target_humidity is not None:
            req.has_target_humidity = True
            req.target_humidity = target_humidity
        self._get_connection().send_message(req)

    async def number_command(self, key: int, state: float) -> None:
        self._get_connection().send_message(NumberCommandRequest(key=key, state=state))

    async def select_command(self, key: int, state: str) -> None:
        self._get_connection().send_message(SelectCommandRequest(key=key, state=state))

    async def siren_command(
        self,
        key: int,
        state: bool | None = None,
        tone: str | None = None,
        volume: float | None = None,
        duration: int | None = None,
    ) -> None:
        req = SirenCommandRequest(key=key)
        if state is not None:
            req.state = state
            req.has_state = True
        if tone is not None:
            req.tone = tone
            req.has_tone = True
        if volume is not None:
            req.volume = volume
            req.has_volume = True
        if duration is not None:
            req.duration = duration
            req.has_duration = True
        self._get_connection().send_message(req)

    async def button_command(self, key: int) -> None:
        self._get_connection().send_message(ButtonCommandRequest(key=key))

    async def lock_command(
        self,
        key: int,
        command: LockCommand,
        code: str | None = None,
    ) -> None:
        req = LockCommandRequest(key=key, command=command)
        if code is not None:
            req.code = code
        self._get_connection().send_message(req)

    async def media_player_command(
        self,
        key: int,
        *,
        command: MediaPlayerCommand | None = None,
        volume: float | None = None,
        media_url: str | None = None,
    ) -> None:
        req = MediaPlayerCommandRequest(key=key)
        if command is not None:
            req.command = command
            req.has_command = True
        if volume is not None:
            req.volume = volume
            req.has_volume = True
        if media_url is not None:
            req.media_url = media_url
            req.has_media_url = True
        self._get_connection().send_message(req)

    async def text_command(self, key: int, state: str) -> None:
        self._get_connection().send_message(TextCommandRequest(key=key, state=state))

    async def execute_service(
        self, service: UserService, data: ExecuteServiceDataType
    ) -> None:
        req = ExecuteServiceRequest(key=service.key)
        args = []
        apiv = self.api_version
        if TYPE_CHECKING:
            assert apiv is not None
        map_single = USER_SERVICE_MAP_SINGLE
        map_array = USER_SERVICE_MAP_ARRAY
        for arg_desc in service.args:
            arg = ExecuteServiceArgument()
            val = data[arg_desc.name]
            if arg_desc.type in map_array:
                attr = getattr(arg, map_array[arg_desc.type])
                attr.extend(val)
            elif arg_desc.type == UserServiceArgType.INT:
                int_type = "int_" if apiv >= APIVersion(1, 3) else "legacy_int"
                setattr(arg, int_type, val)
            else:
                assert arg_desc.type in map_single
                setattr(arg, map_single[arg_desc.type], val)

            args.append(arg)
        # pylint: disable=no-member
        req.args.extend(args)

        self._get_connection().send_message(req)

    async def _request_image(
        self, *, single: bool = False, stream: bool = False
    ) -> None:
        self._get_connection().send_message(
            CameraImageRequest(single=single, stream=stream)
        )

    async def request_single_image(self) -> None:
        await self._request_image(single=True)

    async def request_image_stream(self) -> None:
        await self._request_image(stream=True)

    @property
    def api_version(self) -> APIVersion | None:
        if self._connection is None:
            return None
        return self._connection.api_version

    async def subscribe_voice_assistant(
        self,
        handle_start: Callable[
            [str, int, VoiceAssistantAudioSettingsModel],
            Coroutine[Any, Any, int | None],
        ],
        handle_stop: Callable[[], Coroutine[Any, Any, None]],
    ) -> Callable[[], None]:
        """Subscribes to voice assistant messages from the device.

        handle_start: called when the devices requests a server to send audio data to.
                      This callback is asynchronous and returns the port number the server is started on.

        handle_stop: called when the device has stopped sending audio data and the pipeline should be closed.

        Returns a callback to unsubscribe.
        """
        connection = self._get_connection()

        start_task: asyncio.Task[int | None] | None = None

        def _started(fut: asyncio.Task[int | None]) -> None:
            if self._connection is not None and not fut.cancelled():
                port = fut.result()
                if port is not None:
                    self._connection.send_message(VoiceAssistantResponse(port=port))
                else:
                    _LOGGER.error("Server could not be started")
                    self._connection.send_message(VoiceAssistantResponse(error=True))

        def _on_voice_assistant_request(msg: VoiceAssistantRequest) -> None:
            nonlocal start_task

            command = VoiceAssistantCommand.from_pb(msg)
            if command.start:
                start_task = asyncio.create_task(
                    handle_start(
                        command.conversation_id, command.flags, command.audio_settings
                    )
                )
                start_task.add_done_callback(_started)
                # We hold a reference to the start_task in unsub function
                # so we don't need to add it to the background tasks.
            else:
                self._create_background_task(handle_stop())

        connection.send_message(SubscribeVoiceAssistantRequest(subscribe=True))

        remove_callback = connection.add_message_callback(
            _on_voice_assistant_request, (VoiceAssistantRequest,)
        )

        def unsub() -> None:
            nonlocal start_task

            if self._connection is not None:
                remove_callback()
                self._connection.send_message(
                    SubscribeVoiceAssistantRequest(subscribe=False)
                )

            if start_task is not None and not start_task.cancelled():
                start_task.cancel("Unsubscribing from voice assistant")

        return unsub

    def _create_background_task(self, coro: Coroutine[Any, Any, None]) -> None:
        """Create a background task and add it to the background tasks set."""
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def send_voice_assistant_event(
        self, event_type: VoiceAssistantEventType, data: dict[str, str] | None
    ) -> None:
        req = VoiceAssistantEventResponse(event_type=event_type)
        if data is not None:
            # pylint: disable=no-member
            req.data.extend(
                [
                    VoiceAssistantEventData(name=name, value=value)
                    for name, value in data.items()
                ]
            )
        self._get_connection().send_message(req)

    async def alarm_control_panel_command(
        self,
        key: int,
        command: AlarmControlPanelCommand,
        code: str | None = None,
    ) -> None:
        req = AlarmControlPanelCommandRequest(key=key, command=command)
        if code is not None:
            req.code = code
        self._get_connection().send_message(req)
