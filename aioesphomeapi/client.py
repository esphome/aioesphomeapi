# pylint: disable=unidiomatic-typecheck
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Coroutine
from functools import partial
import logging
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
    BluetoothScannerSetModeRequest,
    BluetoothScannerStateResponse,
    ButtonCommandRequest,
    CameraImageRequest,
    CameraImageResponse,
    ClimateCommandRequest,
    CoverCommandRequest,
    DateCommandRequest,
    DateTimeCommandRequest,
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
    NoiseEncryptionSetKeyRequest,
    NoiseEncryptionSetKeyResponse,
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
    TimeCommandRequest,
    UnsubscribeBluetoothLEAdvertisementsRequest,
    UpdateCommandRequest,
    ValveCommandRequest,
    VoiceAssistantAnnounceFinished,
    VoiceAssistantAnnounceRequest,
    VoiceAssistantAudio,
    VoiceAssistantConfigurationRequest,
    VoiceAssistantConfigurationResponse,
    VoiceAssistantEventData,
    VoiceAssistantEventResponse,
    VoiceAssistantRequest,
    VoiceAssistantResponse,
    VoiceAssistantSetConfiguration,
    VoiceAssistantTimerEventResponse,
)
from .client_base import (
    APIClientBase,
    on_bluetooth_connections_free_response,
    on_bluetooth_device_connection_response,
    on_bluetooth_gatt_notify_data_response,
    on_bluetooth_handle_message,
    on_bluetooth_le_advertising_response,
    on_bluetooth_message_types,
    on_bluetooth_scanner_state_response,
    on_home_assistant_service_response,
    on_state_msg,
    on_subscribe_home_assistant_state_response,
)
from .connection import APIConnection, ConnectionParams, handle_timeout  # noqa: F401
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
    BluetoothScannerMode,
    BluetoothScannerStateResponse as BluetoothScannerStateResponseModel,
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
    NoiseEncryptionSetKeyResponse as NoiseEncryptionSetKeyResponseModel,
    UpdateCommand,
    UserService,
    UserServiceArgType,
    VoiceAssistantAnnounceFinished as VoiceAssistantAnnounceFinishedModel,
    VoiceAssistantAudioData,
    VoiceAssistantAudioSettings as VoiceAssistantAudioSettingsModel,
    VoiceAssistantCommand,
    VoiceAssistantConfigurationResponse as VoiceAssistantConfigurationResponseModel,
    VoiceAssistantEventType,
    VoiceAssistantSubscriptionFlag,
    VoiceAssistantTimerEventType,
    message_types_to_names,
)
from .model_conversions import (
    LIST_ENTITIES_SERVICES_RESPONSE_TYPES,
    SUBSCRIBE_STATES_RESPONSE_TYPES,
)
from .util import create_eager_task

_LOGGER = logging.getLogger(__name__)

DEFAULT_BLE_TIMEOUT = 30.0
DEFAULT_BLE_DISCONNECT_TIMEOUT = 20.0

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


# pylint: disable=too-many-public-methods
class APIClient(APIClientBase):
    """The ESPHome API client.

    This class is the main entrypoint for interacting with the API.

    It is recommended to use this class in combination with the
    ReconnectLogic class to automatically reconnect to the device
    if the connection is lost.
    """

    async def connect(
        self,
        on_stop: Callable[[bool], Coroutine[Any, Any, None]] | None = None,
        login: bool = False,
    ) -> None:
        """Connect to the device."""
        await self.start_resolve_host(on_stop)
        await self.start_connection()
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

    async def start_resolve_host(
        self,
        on_stop: Callable[[bool], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        """Start resolving the host."""
        if self._connection is not None:
            raise APIConnectionError(f"Already connected to {self.log_name}!")
        self._connection = APIConnection(
            self._params,
            partial(self._on_stop, on_stop),
            self._debug_enabled,
            self.log_name,
        )
        await self._execute_connection_coro(self._connection.start_resolve_host())

    async def start_connection(self) -> None:
        """Start connecting to the device."""
        if TYPE_CHECKING:
            assert self._connection is not None
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

    async def device_info(self) -> DeviceInfo:
        resp = await self._get_connection().send_message_await_response(
            DeviceInfoRequest(), DeviceInfoResponse
        )
        info = DeviceInfo.from_pb(resp)
        self._set_name_from_device(info.name)
        return info

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

    def subscribe_states(self, on_state: Callable[[EntityState], None]) -> None:
        """Subscribe to state updates."""
        self._get_connection().send_message_callback_response(
            SubscribeStatesRequest(),
            partial(on_state_msg, on_state, {}),
            SUBSCRIBE_STATES_MSG_TYPES,
        )

    def subscribe_logs(
        self,
        on_log: Callable[[SubscribeLogsResponse], None],
        log_level: LogLevel | None = None,
        dump_config: bool | None = None,
    ) -> Callable[[], None]:
        """Subscribe to logs.

        Returns a callable that can be called to stop
        the callbacks. Calling the callable only
        stops the callbacks. The device will still
        send logs until the logging level is set to
        LogLevel.LOG_LEVEL_NONE.

        To stop the device sending logs completely, call
        with log_level=LogLevel.LOG_LEVEL_NONE, and call the returned
        callable to unsubscribe.
        """
        req = SubscribeLogsRequest()
        if log_level is not None:
            req.level = log_level
        if dump_config is not None:
            req.dump_config = dump_config
        return self._get_connection().send_message_callback_response(
            req, on_log, (SubscribeLogsResponse,)
        )

    def subscribe_service_calls(
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

    def subscribe_bluetooth_le_advertisements(
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

    def subscribe_bluetooth_le_raw_advertisements(
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

    def subscribe_bluetooth_connections_free(
        self,
        on_bluetooth_connections_free_update: Callable[[int, int, list[int]], None],
    ) -> Callable[[], None]:
        return self._get_connection().send_message_callback_response(
            SubscribeBluetoothConnectionsFreeRequest(),
            partial(
                on_bluetooth_connections_free_response,
                on_bluetooth_connections_free_update,
            ),
            (BluetoothConnectionsFreeResponse,),
        )

    def subscribe_bluetooth_scanner_state(
        self,
        on_bluetooth_scanner_state: Callable[
            [BluetoothScannerStateResponseModel], None
        ],
    ) -> Callable[[], None]:
        """Subscribe to Bluetooth scanner state updates."""
        return self._get_connection().add_message_callback(
            partial(
                on_bluetooth_scanner_state_response,
                on_bluetooth_scanner_state,
            ),
            (BluetoothScannerStateResponse,),
        )

    def bluetooth_scanner_set_mode(self, mode: BluetoothScannerMode) -> None:
        """Set the Bluetooth scanner mode."""
        self._get_connection().send_message(BluetoothScannerSetModeRequest(mode=mode))

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
        unhandled_exception = False
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
        except BaseException:
            unhandled_exception = True
            raise
        finally:
            if unhandled_exception or (not connect_ok and not timeout_expired):
                unsub()
            if not timeout_expired:
                timeout_handle.cancel()
            if unhandled_exception:
                # Make sure to disconnect if we had an unhandled exception
                # as otherwise the connection will be left open.
                self._bluetooth_disconnect_no_wait(address)

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

    def _bluetooth_disconnect_no_wait(self, address: int) -> None:
        """Disconnect from a Bluetooth device without waiting for a response."""
        self._get_connection().send_message(
            BluetoothDeviceRequest(
                address=address, request_type=BluetoothDeviceRequestType.DISCONNECT
            )
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

    def subscribe_home_assistant_states(
        self,
        on_state_sub: Callable[[str, str | None], None],
        on_state_request: Callable[[str, str | None], None] | None = None,
    ) -> None:
        self._get_connection().send_message_callback_response(
            SubscribeHomeAssistantStatesRequest(),
            partial(
                on_subscribe_home_assistant_state_response,
                on_state_sub,
                on_state_request,
            ),
            (SubscribeHomeAssistantStateResponse,),
        )

    def send_home_assistant_state(
        self, entity_id: str, attribute: str | None, state: str
    ) -> None:
        self._get_connection().send_message(
            HomeAssistantStateResponse(
                entity_id=entity_id,
                state=state,
                attribute=attribute,
            )
        )

    def cover_command(
        self,
        key: int,
        position: float | None = None,
        tilt: float | None = None,
        stop: bool = False,
        device_id: int = 0,
    ) -> None:
        connection = self._get_connection()
        req = CoverCommandRequest(key=key, device_id=device_id)
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
        elif stop:
            req.legacy_command = LegacyCoverCommand.STOP
            req.has_legacy_command = True
        elif position == 1.0:
            req.legacy_command = LegacyCoverCommand.OPEN
            req.has_legacy_command = True
        elif position == 0.0:
            req.legacy_command = LegacyCoverCommand.CLOSE
            req.has_legacy_command = True
        connection.send_message(req)

    def fan_command(
        self,
        key: int,
        state: bool | None = None,
        speed: FanSpeed | None = None,
        speed_level: int | None = None,
        oscillating: bool | None = None,
        direction: FanDirection | None = None,
        preset_mode: str | None = None,
        device_id: int = 0,
    ) -> None:
        req = FanCommandRequest(key=key, device_id=device_id)
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

    def light_command(  # pylint: disable=too-many-branches
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
        device_id: int = 0,
    ) -> None:
        req = LightCommandRequest(key=key, device_id=device_id)
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
            req.transition_length = round(transition_length * 1000)
        if flash_length is not None:
            req.has_flash_length = True
            req.flash_length = round(flash_length * 1000)
        if effect is not None:
            req.has_effect = True
            req.effect = effect
        self._get_connection().send_message(req)

    def switch_command(self, key: int, state: bool, device_id: int = 0) -> None:
        self._get_connection().send_message(
            SwitchCommandRequest(key=key, state=state, device_id=device_id)
        )

    def climate_command(  # pylint: disable=too-many-branches
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
        device_id: int = 0,
    ) -> None:
        connection = self._get_connection()
        req = ClimateCommandRequest(key=key, device_id=device_id)
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
                req.unused_has_legacy_away = True
                req.unused_legacy_away = preset == ClimatePreset.AWAY
            else:
                req.has_preset = True
                req.preset = preset
        if custom_preset is not None:
            req.has_custom_preset = True
            req.custom_preset = custom_preset
        if target_humidity is not None:
            req.has_target_humidity = True
            req.target_humidity = target_humidity
        connection.send_message(req)

    def number_command(self, key: int, state: float, device_id: int = 0) -> None:
        self._get_connection().send_message(
            NumberCommandRequest(key=key, state=state, device_id=device_id)
        )

    def date_command(
        self, key: int, year: int, month: int, day: int, device_id: int = 0
    ) -> None:
        self._get_connection().send_message(
            DateCommandRequest(
                key=key, year=year, month=month, day=day, device_id=device_id
            )
        )

    def time_command(
        self, key: int, hour: int, minute: int, second: int, device_id: int = 0
    ) -> None:
        self._get_connection().send_message(
            TimeCommandRequest(
                key=key, hour=hour, minute=minute, second=second, device_id=device_id
            )
        )

    def datetime_command(
        self,
        key: int,
        epoch_seconds: int,
        device_id: int = 0,
    ) -> None:
        self._get_connection().send_message(
            DateTimeCommandRequest(
                key=key,
                epoch_seconds=epoch_seconds,
                device_id=device_id,
            )
        )

    def select_command(self, key: int, state: str, device_id: int = 0) -> None:
        self._get_connection().send_message(
            SelectCommandRequest(key=key, state=state, device_id=device_id)
        )

    def siren_command(
        self,
        key: int,
        state: bool | None = None,
        tone: str | None = None,
        volume: float | None = None,
        duration: int | None = None,
        device_id: int = 0,
    ) -> None:
        req = SirenCommandRequest(key=key, device_id=device_id)
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

    def button_command(self, key: int, device_id: int = 0) -> None:
        self._get_connection().send_message(
            ButtonCommandRequest(key=key, device_id=device_id)
        )

    def lock_command(
        self,
        key: int,
        command: LockCommand,
        code: str | None = None,
        device_id: int = 0,
    ) -> None:
        req = LockCommandRequest(key=key, command=command, device_id=device_id)
        if code is not None:
            req.code = code
        self._get_connection().send_message(req)

    def valve_command(
        self,
        key: int,
        position: float | None = None,
        stop: bool = False,
        device_id: int = 0,
    ) -> None:
        req = ValveCommandRequest(key=key, device_id=device_id)
        if position is not None:
            req.has_position = True
            req.position = position
        if stop:
            req.stop = stop
        self._get_connection().send_message(req)

    def media_player_command(
        self,
        key: int,
        *,
        command: MediaPlayerCommand | None = None,
        volume: float | None = None,
        media_url: str | None = None,
        announcement: bool | None = None,
        device_id: int = 0,
    ) -> None:
        req = MediaPlayerCommandRequest(key=key, device_id=device_id)
        if command is not None:
            req.command = command
            req.has_command = True
        if volume is not None:
            req.volume = volume
            req.has_volume = True
        if media_url is not None:
            req.media_url = media_url
            req.has_media_url = True
        if announcement is not None:
            req.announcement = announcement
            req.has_announcement = True
        self._get_connection().send_message(req)

    def text_command(self, key: int, state: str, device_id: int = 0) -> None:
        self._get_connection().send_message(
            TextCommandRequest(key=key, state=state, device_id=device_id)
        )

    def update_command(
        self, key: int, command: UpdateCommand, device_id: int = 0
    ) -> None:
        self._get_connection().send_message(
            UpdateCommandRequest(key=key, command=command, device_id=device_id)
        )

    def execute_service(
        self, service: UserService, data: ExecuteServiceDataType
    ) -> None:
        connection = self._get_connection()
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

        connection.send_message(req)

    def _request_image(self, *, single: bool = False, stream: bool = False) -> None:
        self._get_connection().send_message(
            CameraImageRequest(single=single, stream=stream)
        )

    def request_single_image(self) -> None:
        self._request_image(single=True)

    def request_image_stream(self) -> None:
        self._request_image(stream=True)

    def subscribe_voice_assistant(
        self,
        *,
        handle_start: Callable[
            [str, int, VoiceAssistantAudioSettingsModel, str | None],
            Coroutine[Any, Any, int | None],
        ],
        handle_stop: Callable[[bool], Coroutine[Any, Any, None]],
        handle_audio: (
            Callable[
                [bytes],
                Coroutine[Any, Any, None],
            ]
            | None
        ) = None,
        handle_announcement_finished: (
            Callable[
                [VoiceAssistantAnnounceFinishedModel],
                Coroutine[Any, Any, None],
            ]
            | None
        ) = None,
    ) -> Callable[[], None]:
        """Subscribes to voice assistant messages from the device.

        handle_start: called when the devices requests a server to send audio data to.
                      This callback is asynchronous and returns the port number the server is started on.

        handle_stop: called when the device has stopped sending audio data and the pipeline should be closed or aborted.

        handle_audio: called when a chunk of audio is sent from the device.

        handle_announcement_finished: called when a VoiceAssistantAnnounceFinished message is sent from the device.

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
                wake_word_phrase: str | None = command.wake_word_phrase
                if wake_word_phrase == "":
                    wake_word_phrase = None
                start_task = create_eager_task(
                    handle_start(
                        command.conversation_id,
                        command.flags,
                        command.audio_settings,
                        wake_word_phrase,
                    )
                )
                start_task.add_done_callback(_started)
                # We hold a reference to the start_task in unsub function
                # so we don't need to add it to the background tasks.
            else:
                self._create_background_task(handle_stop(True))

        remove_callbacks = []
        flags = 0
        if handle_audio is not None:
            flags |= VoiceAssistantSubscriptionFlag.API_AUDIO

            def _on_voice_assistant_audio(msg: VoiceAssistantAudio) -> None:
                audio = VoiceAssistantAudioData.from_pb(msg)
                if audio.end:
                    self._create_background_task(handle_stop(False))
                else:
                    self._create_background_task(handle_audio(audio.data))

            remove_callbacks.append(
                connection.add_message_callback(
                    _on_voice_assistant_audio, (VoiceAssistantAudio,)
                )
            )

        connection.send_message(
            SubscribeVoiceAssistantRequest(subscribe=True, flags=flags)
        )

        remove_callbacks.append(
            connection.add_message_callback(
                _on_voice_assistant_request, (VoiceAssistantRequest,)
            )
        )

        if handle_announcement_finished is not None:

            def _on_voice_assistant_announcement_finished(
                msg: VoiceAssistantAnnounceFinished,
            ) -> None:
                finished = VoiceAssistantAnnounceFinishedModel.from_pb(msg)
                self._create_background_task(handle_announcement_finished(finished))

            remove_callbacks.append(
                connection.add_message_callback(
                    _on_voice_assistant_announcement_finished,
                    (VoiceAssistantAnnounceFinished,),
                )
            )

        def unsub() -> None:
            if self._connection is not None:
                for remove_callback in remove_callbacks:
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

    def send_voice_assistant_audio(self, data: bytes) -> None:
        req = VoiceAssistantAudio(data=data)
        self._get_connection().send_message(req)

    def send_voice_assistant_timer_event(
        self,
        event_type: VoiceAssistantTimerEventType,
        timer_id: str,
        name: str | None,
        total_seconds: int,
        seconds_left: int,
        is_active: bool,
    ) -> None:
        req = VoiceAssistantTimerEventResponse(
            event_type=event_type,
            timer_id=timer_id,
            name=name,
            total_seconds=total_seconds,
            seconds_left=seconds_left,
            is_active=is_active,
        )
        self._get_connection().send_message(req)

    async def send_voice_assistant_announcement_await_response(
        self,
        media_id: str,
        timeout: float,
        text: str = "",
        preannounce_media_id: str = "",
        start_conversation: bool = False,
    ) -> VoiceAssistantAnnounceFinishedModel:
        resp = await self._get_connection().send_message_await_response(
            VoiceAssistantAnnounceRequest(
                media_id=media_id,
                text=text,
                preannounce_media_id=preannounce_media_id,
                start_conversation=start_conversation,
            ),
            VoiceAssistantAnnounceFinished,
            timeout,
        )
        return VoiceAssistantAnnounceFinishedModel.from_pb(resp)

    async def get_voice_assistant_configuration(
        self, timeout: float
    ) -> VoiceAssistantConfigurationResponseModel:
        resp = await self._get_connection().send_message_await_response(
            VoiceAssistantConfigurationRequest(),
            VoiceAssistantConfigurationResponse,
            timeout,
        )
        return VoiceAssistantConfigurationResponseModel.from_pb(resp)

    async def set_voice_assistant_configuration(
        self, active_wake_words: list[str]
    ) -> None:
        req = VoiceAssistantSetConfiguration(active_wake_words=active_wake_words)
        self._get_connection().send_message(req)

    def alarm_control_panel_command(
        self,
        key: int,
        command: AlarmControlPanelCommand,
        code: str | None = None,
        device_id: int = 0,
    ) -> None:
        req = AlarmControlPanelCommandRequest(
            key=key, command=command, device_id=device_id
        )
        if code is not None:
            req.code = code
        self._get_connection().send_message(req)

    async def noise_encryption_set_key(
        self,
        key: bytes,
    ) -> bool:
        """Set the noise encryption key."""
        req = NoiseEncryptionSetKeyRequest(key=key)
        resp = await self._get_connection().send_message_await_response(
            req, NoiseEncryptionSetKeyResponse
        )
        return NoiseEncryptionSetKeyResponseModel.from_pb(resp).success
