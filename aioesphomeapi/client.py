from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Coroutine
from functools import partial
from typing import TYPE_CHECKING, Any, Callable, Union, cast

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
    BluetoothLERawAdvertisement,
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
    VoiceAssistantAudioSettings,
    VoiceAssistantEventData,
    VoiceAssistantEventResponse,
    VoiceAssistantRequest,
    VoiceAssistantResponse,
)
from .client_callbacks import (
    on_ble_raw_advertisement_response,
    on_bluetooth_connections_free_response,
    on_bluetooth_gatt_notify_data_response,
    on_bluetooth_le_advertising_response,
    on_home_assistant_service_response,
    on_state_msg,
    on_subscribe_home_assistant_state_response,
)
from .connection import APIConnection, ConnectionParams
from .core import (
    APIConnectionError,
    BluetoothGATTAPIError,
    TimeoutAPIError,
    UnhandledAPIConnectionError,
    to_human_readable_address,
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
    VoiceAssistantCommand,
    VoiceAssistantEventType,
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
    __slots__ = (
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
        """
        self._params = ConnectionParams(
            address=str(address),
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
        return self._params.address

    def _set_log_name(self) -> None:
        """Set the log name of the device."""
        resolved_address: str | None = None
        if self._connection and self._connection.resolved_addr_info:
            resolved_address = self._connection.resolved_addr_info.sockaddr.address
        self.log_name = build_log_name(
            self.cached_name,
            self.address,
            resolved_address,
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
        on_stop: Callable[[bool], Awaitable[None]] | None = None,
        login: bool = False,
    ) -> None:
        """Connect to the device."""
        await self.start_connection(on_stop)
        await self.finish_connection(login)

    async def start_connection(
        self,
        on_stop: Callable[[bool], Awaitable[None]] | None = None,
    ) -> None:
        """Start connecting to the device."""
        if self._connection is not None:
            raise APIConnectionError(f"Already connected to {self.log_name}!")

        async def _on_stop(expected_disconnect: bool) -> None:
            # Hook into on_stop handler to clear connection when stopped
            self._connection = None
            if on_stop is not None:
                await on_stop(expected_disconnect)

        self._connection = APIConnection(self._params, _on_stop, log_name=self.log_name)

        try:
            await self._connection.start_connection()
        except APIConnectionError:
            self._connection = None
            raise
        except Exception as e:
            self._connection = None
            raise UnhandledAPIConnectionError(
                f"Unexpected error while connecting to {self.log_name}: {e}"
            ) from e
        # If we resolved the address, we should set the log name now
        if self._connection.resolved_addr_info:
            self._set_log_name()

    async def finish_connection(
        self,
        login: bool = False,
    ) -> None:
        """Finish connecting to the device."""
        if TYPE_CHECKING:
            assert self._connection is not None
        try:
            await self._connection.finish_connection(login=login)
        except APIConnectionError:
            self._connection = None
            raise
        except Exception as e:
            self._connection = None
            raise UnhandledAPIConnectionError(
                f"Unexpected error while connecting to {self.log_name}: {e}"
            ) from e
        if received_name := self._connection.received_name:
            self._set_name_from_device(received_name)

    async def disconnect(self, force: bool = False) -> None:
        if self._connection is None:
            return
        if force:
            await self._connection.force_disconnect()
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
        response_types = LIST_ENTITIES_SERVICES_RESPONSE_TYPES
        msg_types = LIST_ENTITIES_MSG_TYPES

        def do_append(msg: message.Message) -> bool:
            return not isinstance(msg, ListEntitiesDoneResponse)

        def do_stop(msg: message.Message) -> bool:
            return isinstance(msg, ListEntitiesDoneResponse)

        resp = await self._get_connection().send_messages_await_response_complex(
            (ListEntitiesRequest(),), do_append, do_stop, msg_types, 60
        )
        entities: list[EntityInfo] = []
        services: list[UserService] = []
        for msg in resp:
            if isinstance(msg, ListEntitiesServicesResponse):
                services.append(UserService.from_pb(msg))
                continue
            cls = response_types[type(msg)]
            assert cls is not None
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

    def _filter_bluetooth_message(
        self,
        address: int,
        handle: int,
        msg: message.Message,
    ) -> bool:
        """Handle a Bluetooth message."""
        if TYPE_CHECKING:
            assert isinstance(
                msg,
                (
                    BluetoothGATTErrorResponse,
                    BluetoothGATTNotifyResponse,
                    BluetoothGATTReadResponse,
                    BluetoothGATTWriteResponse,
                ),
            )
        return bool(msg.address == address and msg.handle == handle)

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
        message_filter = partial(self._filter_bluetooth_message, address, handle)
        resp = await self._get_connection().send_messages_await_response_complex(
            (request,),
            message_filter,
            message_filter,
            (response_type, BluetoothGATTErrorResponse),
            timeout,
        )

        if isinstance(resp[0], BluetoothGATTErrorResponse):
            raise BluetoothGATTAPIError(BluetoothGATTError.from_pb(resp[0]))

        return resp[0]

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

        def unsub() -> None:
            if self._connection is not None:
                unsub_callback()
                self._connection.send_message(
                    UnsubscribeBluetoothLEAdvertisementsRequest()
                )

        return unsub

    async def subscribe_bluetooth_le_raw_advertisements(
        self, on_advertisements: Callable[[list[BluetoothLERawAdvertisement]], None]
    ) -> Callable[[], None]:
        unsub_callback = self._get_connection().send_message_callback_response(
            SubscribeBluetoothLEAdvertisementsRequest(
                flags=BluetoothProxySubscriptionFlag.RAW_ADVERTISEMENTS
            ),
            partial(on_ble_raw_advertisement_response, on_advertisements),
            (BluetoothLERawAdvertisementsResponse,),
        )

        def unsub() -> None:
            if self._connection is not None:
                unsub_callback()
                self._connection.send_message(
                    UnsubscribeBluetoothLEAdvertisementsRequest()
                )

        return unsub

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

    def _handle_timeout(self, fut: asyncio.Future[None]) -> None:
        """Handle a timeout."""
        if fut.done():
            return
        fut.set_exception(asyncio.TimeoutError)

    def _on_bluetooth_device_connection_response(
        self,
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
        debug = _LOGGER.isEnabledFor(logging.DEBUG)
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

        if debug:
            _LOGGER.debug("%s: Using connection version %s", address, request_type)

        unsub = self._get_connection().send_message_callback_response(
            BluetoothDeviceRequest(
                address=address,
                request_type=request_type,
                has_address_type=address_type is not None,
                address_type=address_type or 0,
            ),
            partial(
                self._on_bluetooth_device_connection_response,
                connect_future,
                address,
                on_bluetooth_connection_state,
            ),
            (BluetoothDeviceConnectionResponse,),
        )

        loop = self._loop
        timeout_handle = loop.call_at(
            loop.time() + timeout, self._handle_timeout, connect_future
        )
        timeout_expired = False
        connect_ok = False
        try:
            await connect_future
            connect_ok = True
        except asyncio.TimeoutError as err:
            timeout_expired = True
            # Disconnect before raising the exception to ensure
            # the slot is recovered before the timeout is raised
            # to avoid race were we run out even though we have a slot.
            addr = to_human_readable_address(address)
            if debug:
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
            if not connect_ok:
                try:
                    unsub()
                except (KeyError, ValueError):
                    _LOGGER.warning(
                        "%s: Bluetooth device connection canceled but already unsubscribed",
                        to_human_readable_address(address),
                    )
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
            if _LOGGER.isEnabledFor(logging.DEBUG):
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
        def predicate_func(
            msg: BluetoothDevicePairingResponse | BluetoothDeviceConnectionResponse,
        ) -> bool:
            if msg.address != address:
                return False
            if isinstance(msg, BluetoothDeviceConnectionResponse):
                raise APIConnectionError(
                    "Peripheral changed connections status while pairing"
                )
            return True

        return BluetoothDevicePairing.from_pb(
            await self._bluetooth_device_request(
                address,
                BluetoothDeviceRequestType.PAIR,
                predicate_func,
                (
                    BluetoothDevicePairingResponse,
                    BluetoothDeviceConnectionResponse,
                ),
                timeout,
            )
        )

    async def bluetooth_device_unpair(
        self, address: int, timeout: float = DEFAULT_BLE_TIMEOUT
    ) -> BluetoothDeviceUnpairing:
        return BluetoothDeviceUnpairing.from_pb(
            await self._bluetooth_device_request(
                address,
                BluetoothDeviceRequestType.UNPAIR,
                lambda msg: msg.address == address,
                (BluetoothDeviceUnpairingResponse,),
                timeout,
            )
        )

    async def bluetooth_device_clear_cache(
        self, address: int, timeout: float = DEFAULT_BLE_TIMEOUT
    ) -> BluetoothDeviceClearCache:
        return BluetoothDeviceClearCache.from_pb(
            await self._bluetooth_device_request(
                address,
                BluetoothDeviceRequestType.CLEAR_CACHE,
                lambda msg: msg.address == address,
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

    async def _bluetooth_device_request(
        self,
        address: int,
        request_type: BluetoothDeviceRequestType,
        predicate_func: Callable[[BluetoothDeviceConnectionResponse], bool],
        msg_types: tuple[type[message.Message], ...],
        timeout: float,
    ) -> message.Message:
        [response] = await self._get_connection().send_messages_await_response_complex(
            (
                BluetoothDeviceRequest(
                    address=address,
                    request_type=request_type,
                ),
            ),
            predicate_func,
            predicate_func,
            msg_types,
            timeout,
        )
        return response

    async def bluetooth_gatt_get_services(
        self, address: int
    ) -> ESPHomeBluetoothGATTServices:
        append_types = (BluetoothGATTGetServicesResponse, BluetoothGATTErrorResponse)
        stop_types = (BluetoothGATTGetServicesDoneResponse, BluetoothGATTErrorResponse)

        def do_append(msg: message.Message) -> bool:
            return isinstance(msg, append_types) and msg.address == address

        def do_stop(msg: message.Message) -> bool:
            return isinstance(msg, stop_types) and msg.address == address

        resp = await self._get_connection().send_messages_await_response_complex(
            (BluetoothGATTGetServicesRequest(address=address),),
            do_append,
            do_stop,
            (
                BluetoothGATTGetServicesResponse,
                BluetoothGATTGetServicesDoneResponse,
                BluetoothGATTErrorResponse,
            ),
            DEFAULT_BLE_TIMEOUT,
        )
        services = []
        for msg in resp:
            if isinstance(msg, BluetoothGATTErrorResponse):
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
            BluetoothGATTReadRequest(),
            address,
            handle,
            timeout,
        )

    async def bluetooth_gatt_write(
        self,
        address: int,
        handle: int,
        data: bytes,
        response: bool,
        timeout: float = DEFAULT_BLE_TIMEOUT,
    ) -> None:
        req = BluetoothGATTWriteRequest()
        req.address = address
        req.handle = handle
        req.response = response
        req.data = data

        if not response:
            self._get_connection().send_message(req)
            return

        await self._send_bluetooth_message_await_response(
            address,
            handle,
            req,
            BluetoothGATTWriteResponse,
            timeout=timeout,
        )

    async def bluetooth_gatt_read_descriptor(
        self,
        address: int,
        handle: int,
        timeout: float = DEFAULT_BLE_TIMEOUT,
    ) -> bytearray:
        """Read a GATT descriptor."""
        return await self._bluetooth_gatt_read(
            BluetoothGATTReadDescriptorRequest(),
            address,
            handle,
            timeout,
        )

    async def _bluetooth_gatt_read(
        self,
        req: BluetoothGATTReadDescriptorRequest | BluetoothGATTReadRequest,
        address: int,
        handle: int,
        timeout: float,
    ) -> bytearray:
        """Perform a GATT read."""
        req.address = address
        req.handle = handle
        resp = await self._send_bluetooth_message_await_response(
            address,
            handle,
            req,
            BluetoothGATTReadResponse,
            timeout=timeout,
        )
        if TYPE_CHECKING:
            assert isinstance(resp, BluetoothGATTReadResponse)
        return bytearray(resp.data)

    async def bluetooth_gatt_write_descriptor(
        self,
        address: int,
        handle: int,
        data: bytes,
        timeout: float = DEFAULT_BLE_TIMEOUT,
        wait_for_response: bool = True,
    ) -> None:
        req = BluetoothGATTWriteDescriptorRequest()
        req.address = address
        req.handle = handle
        req.data = data

        if not wait_for_response:
            self._get_connection().send_message(req)
            return

        await self._send_bluetooth_message_await_response(
            address,
            handle,
            req,
            BluetoothGATTWriteResponse,
            timeout=timeout,
        )

    async def bluetooth_gatt_start_notify(
        self,
        address: int,
        handle: int,
        on_bluetooth_gatt_notify: Callable[[int, bytearray], None],
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
        req = CoverCommandRequest()
        req.key = key
        apiv = cast(APIVersion, self.api_version)
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
    ) -> None:
        req = FanCommandRequest()
        req.key = key
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
        req = LightCommandRequest()
        req.key = key
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
        req = SwitchCommandRequest()
        req.key = key
        req.state = state

        self._get_connection().send_message(req)

    async def climate_command(
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
    ) -> None:
        req = ClimateCommandRequest()
        req.key = key
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
            apiv = cast(APIVersion, self.api_version)
            if apiv < APIVersion(1, 5):
                req.has_legacy_away = True
                req.legacy_away = preset == ClimatePreset.AWAY
            else:
                req.has_preset = True
                req.preset = preset
        if custom_preset is not None:
            req.has_custom_preset = True
            req.custom_preset = custom_preset

        self._get_connection().send_message(req)

    async def number_command(self, key: int, state: float) -> None:
        req = NumberCommandRequest()
        req.key = key
        req.state = state

        self._get_connection().send_message(req)

    async def select_command(self, key: int, state: str) -> None:
        req = SelectCommandRequest()
        req.key = key
        req.state = state

        self._get_connection().send_message(req)

    async def siren_command(
        self,
        key: int,
        state: bool | None = None,
        tone: str | None = None,
        volume: float | None = None,
        duration: int | None = None,
    ) -> None:
        req = SirenCommandRequest()
        req.key = key
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
        req = ButtonCommandRequest()
        req.key = key

        self._get_connection().send_message(req)

    async def lock_command(
        self,
        key: int,
        command: LockCommand,
        code: str | None = None,
    ) -> None:
        req = LockCommandRequest()
        req.key = key
        req.command = command
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
        req = MediaPlayerCommandRequest()
        req.key = key
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
        req = TextCommandRequest()
        req.key = key
        req.state = state

        self._get_connection().send_message(req)

    async def execute_service(
        self, service: UserService, data: ExecuteServiceDataType
    ) -> None:
        req = ExecuteServiceRequest()
        req.key = service.key
        args = []
        for arg_desc in service.args:
            arg = ExecuteServiceArgument()
            val = data[arg_desc.name]
            apiv = cast(APIVersion, self.api_version)
            int_type = "int_" if apiv >= APIVersion(1, 3) else "legacy_int"
            map_single = {
                UserServiceArgType.BOOL: "bool_",
                UserServiceArgType.INT: int_type,
                UserServiceArgType.FLOAT: "float_",
                UserServiceArgType.STRING: "string_",
            }
            map_array = {
                UserServiceArgType.BOOL_ARRAY: "bool_array",
                UserServiceArgType.INT_ARRAY: "int_array",
                UserServiceArgType.FLOAT_ARRAY: "float_array",
                UserServiceArgType.STRING_ARRAY: "string_array",
            }
            if arg_desc.type in map_array:
                attr = getattr(arg, map_array[arg_desc.type])
                attr.extend(val)
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
        req = CameraImageRequest()
        req.single = single
        req.stream = stream

        self._get_connection().send_message(req)

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
            [str, int, VoiceAssistantAudioSettings], Coroutine[Any, Any, int | None]
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
                stop_task = asyncio.create_task(handle_stop())
                self._background_tasks.add(stop_task)
                stop_task.add_done_callback(self._background_tasks.discard)

        connection.send_message(SubscribeVoiceAssistantRequest(subscribe=True))

        remove_callback = connection.add_message_callback(
            _on_voice_assistant_request, (VoiceAssistantRequest,)
        )

        def unsub() -> None:
            if self._connection is not None:
                remove_callback()
                self._connection.send_message(
                    SubscribeVoiceAssistantRequest(subscribe=False)
                )

            if start_task is not None and not start_task.cancelled():
                start_task.cancel("Unsubscribing from voice assistant")

        return unsub

    def send_voice_assistant_event(
        self, event_type: VoiceAssistantEventType, data: dict[str, str] | None
    ) -> None:
        req = VoiceAssistantEventResponse()
        req.event_type = event_type

        data_args = []
        if data is not None:
            for name, value in data.items():
                arg = VoiceAssistantEventData()
                arg.name = name
                arg.value = value
                data_args.append(arg)

        # pylint: disable=no-member
        req.data.extend(data_args)

        self._get_connection().send_message(req)

    async def alarm_control_panel_command(
        self,
        key: int,
        command: AlarmControlPanelCommand,
        code: str | None = None,
    ) -> None:
        req = AlarmControlPanelCommandRequest()
        req.key = key
        req.command = command
        if code is not None:
            req.code = code

        self._get_connection().send_message(req)
