# pylint: disable=too-many-lines
import asyncio
import logging
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
)

import async_timeout
from google.protobuf import message

from .api_pb2 import (  # type: ignore
    BinarySensorStateResponse,
    BluetoothConnectionsFreeResponse,
    BluetoothDeviceConnectionResponse,
    BluetoothDeviceRequest,
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
    CoverCommandRequest,
    CoverStateResponse,
    DeviceInfoRequest,
    DeviceInfoResponse,
    ExecuteServiceArgument,
    ExecuteServiceRequest,
    FanCommandRequest,
    FanStateResponse,
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
from .connection import APIConnection, ConnectionParams
from .core import (
    APIConnectionError,
    BluetoothGATTAPIError,
    TimeoutAPIError,
    to_human_readable_address,
)
from .host_resolver import ZeroconfInstanceType
from .model import (
    APIVersion,
    BinarySensorInfo,
    BinarySensorState,
    BluetoothConnectionsFree,
    BluetoothDeviceConnection,
    BluetoothDeviceRequestType,
    BluetoothGATTError,
    BluetoothGATTRead,
    BluetoothGATTServices,
    BluetoothLEAdvertisement,
    ButtonInfo,
    CameraInfo,
    CameraState,
    ClimateFanMode,
    ClimateInfo,
    ClimateMode,
    ClimatePreset,
    ClimateState,
    ClimateSwingMode,
    CoverInfo,
    CoverState,
    DeviceInfo,
    EntityInfo,
    EntityState,
    ESPHomeBluetoothGATTServices,
    FanDirection,
    FanInfo,
    FanSpeed,
    FanState,
    HomeassistantServiceCall,
    LegacyCoverCommand,
    LightInfo,
    LightState,
    LockCommand,
    LockEntityState,
    LockInfo,
    LogLevel,
    MediaPlayerCommand,
    MediaPlayerEntityState,
    MediaPlayerInfo,
    NumberInfo,
    NumberState,
    SelectInfo,
    SelectState,
    SensorInfo,
    SensorState,
    SirenInfo,
    SirenState,
    SwitchInfo,
    SwitchState,
    TextSensorInfo,
    TextSensorState,
    UserService,
    UserServiceArgType,
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_BLE_TIMEOUT = 30.0
DEFAULT_BLE_DISCONNECT_TIMEOUT = 5.0

ExecuteServiceDataType = Dict[
    str, Union[bool, int, float, str, List[bool], List[int], List[float], List[str]]
]


# pylint: disable=too-many-public-methods
class APIClient:
    def __init__(
        self,
        address: str,
        port: int,
        password: Optional[str],
        *,
        client_info: str = "aioesphomeapi",
        keepalive: float = 15.0,
        zeroconf_instance: ZeroconfInstanceType = None,
        noise_psk: Optional[str] = None,
        expected_name: Optional[str] = None,
    ):
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
            address=address,
            port=port,
            password=password,
            client_info=client_info,
            keepalive=keepalive,
            zeroconf_instance=zeroconf_instance,
            # treat empty psk string as missing (like password)
            noise_psk=noise_psk or None,
            expected_name=expected_name,
        )
        self._connection: Optional[APIConnection] = None
        self._cached_name: Optional[str] = None

    @property
    def expected_name(self) -> Optional[str]:
        return self._params.expected_name

    @expected_name.setter
    def expected_name(self, value: Optional[str]) -> None:
        self._params.expected_name = value

    @property
    def address(self) -> str:
        return self._params.address

    @property
    def _log_name(self) -> str:
        if self._cached_name is not None:
            return f"{self._cached_name} @ {self.address}"
        return self.address

    async def connect(
        self,
        on_stop: Optional[Callable[[], Awaitable[None]]] = None,
        login: bool = False,
    ) -> None:
        if self._connection is not None:
            raise APIConnectionError(f"Already connected to {self._log_name}!")

        async def _on_stop() -> None:
            # Hook into on_stop handler to clear connection when stopped
            self._connection = None
            if on_stop is not None:
                await on_stop()

        self._connection = APIConnection(self._params, _on_stop)
        self._connection.log_name = self._log_name

        try:
            await self._connection.connect(login=login)
        except APIConnectionError:
            self._connection = None
            raise
        except Exception as e:
            self._connection = None
            raise APIConnectionError(
                f"Unexpected error while connecting to {self._log_name}: {e}"
            ) from e

    async def disconnect(self, force: bool = False) -> None:
        if self._connection is None:
            return
        if force:
            await self._connection.force_disconnect()
        else:
            await self._connection.disconnect()

    def _check_connected(self) -> None:
        if self._connection is None:
            raise APIConnectionError(f"Not connected to {self._log_name}!")
        if not self._connection.is_connected:
            raise APIConnectionError(f"Connection not done for {self._log_name}!")

    def _check_authenticated(self) -> None:
        self._check_connected()
        assert self._connection is not None
        if not self._connection.is_authenticated:
            raise APIConnectionError(f"Not authenticated for {self._log_name}!")

    async def device_info(self) -> DeviceInfo:
        self._check_connected()
        assert self._connection is not None
        resp = await self._connection.send_message_await_response(
            DeviceInfoRequest(), DeviceInfoResponse
        )
        info = DeviceInfo.from_pb(resp)
        self._cached_name = info.name
        self._connection.log_name = self._log_name
        return info

    async def list_entities_services(
        self,
    ) -> Tuple[List[EntityInfo], List[UserService]]:
        self._check_authenticated()
        response_types: Dict[Any, Optional[Type[EntityInfo]]] = {
            ListEntitiesBinarySensorResponse: BinarySensorInfo,
            ListEntitiesButtonResponse: ButtonInfo,
            ListEntitiesCoverResponse: CoverInfo,
            ListEntitiesFanResponse: FanInfo,
            ListEntitiesLightResponse: LightInfo,
            ListEntitiesNumberResponse: NumberInfo,
            ListEntitiesSelectResponse: SelectInfo,
            ListEntitiesSensorResponse: SensorInfo,
            ListEntitiesSirenResponse: SirenInfo,
            ListEntitiesSwitchResponse: SwitchInfo,
            ListEntitiesTextSensorResponse: TextSensorInfo,
            ListEntitiesServicesResponse: None,
            ListEntitiesCameraResponse: CameraInfo,
            ListEntitiesClimateResponse: ClimateInfo,
            ListEntitiesLockResponse: LockInfo,
            ListEntitiesMediaPlayerResponse: MediaPlayerInfo,
        }
        msg_types = (ListEntitiesDoneResponse, *response_types)

        def do_append(msg: message.Message) -> bool:
            return not isinstance(msg, ListEntitiesDoneResponse)

        def do_stop(msg: message.Message) -> bool:
            return isinstance(msg, ListEntitiesDoneResponse)

        assert self._connection is not None
        resp = await self._connection.send_message_await_response_complex(
            ListEntitiesRequest(), do_append, do_stop, msg_types, timeout=60
        )
        entities: List[EntityInfo] = []
        services: List[UserService] = []
        for msg in resp:
            if isinstance(msg, ListEntitiesServicesResponse):
                services.append(UserService.from_pb(msg))
                continue
            cls = response_types[type(msg)]
            assert cls is not None
            entities.append(cls.from_pb(msg))
        return entities, services

    async def subscribe_states(self, on_state: Callable[[EntityState], None]) -> None:
        self._check_authenticated()
        image_stream: Dict[int, bytes] = {}
        response_types: Dict[Any, Type[EntityState]] = {
            BinarySensorStateResponse: BinarySensorState,
            CoverStateResponse: CoverState,
            FanStateResponse: FanState,
            LightStateResponse: LightState,
            NumberStateResponse: NumberState,
            SelectStateResponse: SelectState,
            SensorStateResponse: SensorState,
            SirenStateResponse: SirenState,
            SwitchStateResponse: SwitchState,
            TextSensorStateResponse: TextSensorState,
            ClimateStateResponse: ClimateState,
            LockStateResponse: LockEntityState,
            MediaPlayerStateResponse: MediaPlayerEntityState,
        }
        msg_types = (*response_types, CameraImageResponse)

        def on_msg(msg: message.Message) -> None:
            msg_type = type(msg)
            cls = response_types.get(msg_type)
            if cls:
                on_state(cls.from_pb(msg))
            elif isinstance(msg, CameraImageResponse):
                data = image_stream.pop(msg.key, bytes()) + msg.data
                if msg.done:
                    # Return CameraState with the merged data
                    on_state(CameraState(key=msg.key, data=data))
                else:
                    image_stream[msg.key] = data

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeStatesRequest(), on_msg, msg_types
        )

    async def subscribe_logs(
        self,
        on_log: Callable[[SubscribeLogsResponse], None],
        log_level: Optional[LogLevel] = None,
        dump_config: Optional[bool] = None,
    ) -> None:
        self._check_authenticated()

        def on_msg(msg: SubscribeLogsResponse) -> None:
            on_log(msg)

        req = SubscribeLogsRequest()
        if log_level is not None:
            req.level = log_level
        if dump_config is not None:
            req.dump_config = dump_config
        assert self._connection is not None
        await self._connection.send_message_callback_response(
            req, on_msg, (SubscribeLogsResponse,)
        )

    async def subscribe_service_calls(
        self, on_service_call: Callable[[HomeassistantServiceCall], None]
    ) -> None:
        self._check_authenticated()

        def on_msg(msg: HomeassistantServiceResponse) -> None:
            on_service_call(HomeassistantServiceCall.from_pb(msg))

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeHomeassistantServicesRequest(),
            on_msg,
            (HomeassistantServiceResponse,),
        )

    async def _send_bluetooth_message_await_response(
        self,
        address: int,
        handle: int,
        request: message.Message,
        response_type: Type[message.Message],
        timeout: float = 10.0,
    ) -> message.Message:
        self._check_authenticated()
        msg_types = (response_type, BluetoothGATTErrorResponse)
        assert self._connection is not None

        def is_response(msg: message.Message) -> bool:
            return (
                isinstance(msg, msg_types)
                and msg.address == address  # type: ignore[union-attr]
                and msg.handle == handle  # type: ignore[union-attr]
            )

        resp = await self._connection.send_message_await_response_complex(
            request, is_response, is_response, msg_types, timeout=timeout
        )

        if isinstance(resp[0], BluetoothGATTErrorResponse):
            raise BluetoothGATTAPIError(BluetoothGATTError.from_pb(resp[0]))

        return resp[0]

    async def subscribe_bluetooth_le_advertisements(
        self, on_bluetooth_le_advertisement: Callable[[BluetoothLEAdvertisement], None]
    ) -> Callable[[], None]:
        self._check_authenticated()
        msg_types = (BluetoothLEAdvertisementResponse,)

        def on_msg(msg: BluetoothLEAdvertisementResponse) -> None:
            on_bluetooth_le_advertisement(BluetoothLEAdvertisement.from_pb(msg))

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeBluetoothLEAdvertisementsRequest(), on_msg, msg_types
        )

        def unsub() -> None:
            if self._connection is not None:
                self._connection.remove_message_callback(on_msg, msg_types)

        return unsub

    async def subscribe_bluetooth_connections_free(
        self, on_bluetooth_connections_free_update: Callable[[int, int], None]
    ) -> Callable[[], None]:
        self._check_authenticated()
        msg_types = (BluetoothConnectionsFreeResponse,)

        def on_msg(msg: BluetoothConnectionsFreeResponse) -> None:
            resp = BluetoothConnectionsFree.from_pb(msg)
            on_bluetooth_connections_free_update(resp.free, resp.limit)

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeBluetoothConnectionsFreeRequest(), on_msg, msg_types
        )

        def unsub() -> None:
            if self._connection is not None:
                self._connection.remove_message_callback(on_msg, msg_types)

        return unsub

    async def bluetooth_device_connect(  # pylint: disable=too-many-locals
        self,
        address: int,
        on_bluetooth_connection_state: Callable[[bool, int, int], None],
        timeout: float = DEFAULT_BLE_TIMEOUT,
        disconnect_timeout: float = DEFAULT_BLE_DISCONNECT_TIMEOUT,
        version: int = 1,
        has_cache: bool = False,
        address_type: Optional[int] = None,
    ) -> Callable[[], None]:
        self._check_authenticated()
        msg_types = (BluetoothDeviceConnectionResponse,)

        event = asyncio.Event()

        def on_msg(msg: BluetoothDeviceConnectionResponse) -> None:
            resp = BluetoothDeviceConnection.from_pb(msg)
            if address == resp.address:
                on_bluetooth_connection_state(resp.connected, resp.mtu, resp.error)
                event.set()

        assert self._connection is not None
        if has_cache:
            # Version 3 with cache: requestor has services and mtu cached
            _LOGGER.debug("%s: Using connection version 3 with cache", address)
            request_type = BluetoothDeviceRequestType.CONNECT_V3_WITH_CACHE
        elif version >= 3:
            # Version 3 without cache: esp will wipe the service list after sending to save memory
            _LOGGER.debug("%s: Using connection version 3 without cache", address)
            request_type = BluetoothDeviceRequestType.CONNECT_V3_WITHOUT_CACHE
        else:
            # Older than v3 without cache: esp will hold the service list in memory for the duration
            # of the connection. This can crash the esp if the service list is too large.
            _LOGGER.debug("%s: Using connection version 1", address)
            request_type = BluetoothDeviceRequestType.CONNECT

        await self._connection.send_message_callback_response(
            BluetoothDeviceRequest(
                address=address,
                request_type=request_type,
                has_address_type=address_type is not None,
                address_type=address_type or 0,
            ),
            on_msg,
            msg_types,
        )

        def unsub() -> None:
            if self._connection is not None:
                self._connection.remove_message_callback(on_msg, msg_types)

        try:
            try:
                async with async_timeout.timeout(timeout):
                    await event.wait()
            except asyncio.TimeoutError as err:
                # Disconnect before raising the exception to ensure
                # the slot is recovered before the timeout is raised
                # to avoid race were we run out even though we have a slot.
                await self.bluetooth_device_disconnect(address)
                addr = to_human_readable_address(address)
                _LOGGER.debug("%s: Connecting timed out, waiting for disconnect", addr)
                try:
                    async with async_timeout.timeout(disconnect_timeout):
                        await event.wait()
                        disconnect_timed_out = False
                except asyncio.TimeoutError:
                    disconnect_timed_out = True
                _LOGGER.debug(
                    "%s: Disconnect timed out: %s", addr, disconnect_timed_out
                )
                try:
                    unsub()
                except (KeyError, ValueError):
                    _LOGGER.warning(
                        "%s: Bluetooth device connection timed out but already unsubscribed",
                        addr,
                    )
                raise TimeoutAPIError(
                    f"Timeout waiting for connect response while connecting to {addr} "
                    f"after {timeout}s, disconnect timed out: {disconnect_timed_out}, "
                    f" after {disconnect_timeout}s"
                ) from err
        except asyncio.CancelledError:
            try:
                unsub()
            except (KeyError, ValueError):
                _LOGGER.warning(
                    "%s: Bluetooth device connection canceled but already unsubscribed",
                    addr,
                )
            raise

        return unsub

    async def bluetooth_device_disconnect(self, address: int) -> None:
        self._check_authenticated()

        assert self._connection is not None
        await self._connection.send_message(
            BluetoothDeviceRequest(
                address=address,
                request_type=BluetoothDeviceRequestType.DISCONNECT,
            )
        )

    async def bluetooth_gatt_get_services(
        self, address: int
    ) -> ESPHomeBluetoothGATTServices:
        self._check_authenticated()
        msg_types = (
            BluetoothGATTGetServicesResponse,
            BluetoothGATTGetServicesDoneResponse,
            BluetoothGATTErrorResponse,
        )
        append_types = (BluetoothGATTGetServicesResponse, BluetoothGATTErrorResponse)
        stop_types = (BluetoothGATTGetServicesDoneResponse, BluetoothGATTErrorResponse)

        def do_append(msg: message.Message) -> bool:
            return isinstance(msg, append_types) and msg.address == address

        def do_stop(msg: message.Message) -> bool:
            return isinstance(msg, stop_types) and msg.address == address

        assert self._connection is not None
        resp = await self._connection.send_message_await_response_complex(
            BluetoothGATTGetServicesRequest(address=address),
            do_append,
            do_stop,
            msg_types,
            timeout=DEFAULT_BLE_TIMEOUT,
        )
        services = []
        for msg in resp:
            if isinstance(msg, BluetoothGATTErrorResponse):
                raise BluetoothGATTAPIError(BluetoothGATTError.from_pb(msg))

            services.extend(BluetoothGATTServices.from_pb(msg).services)

        return ESPHomeBluetoothGATTServices(address=address, services=services)

    async def bluetooth_gatt_read(
        self,
        address: int,
        handle: int,
        timeout: float = DEFAULT_BLE_TIMEOUT,
    ) -> bytearray:
        req = BluetoothGATTReadRequest()
        req.address = address
        req.handle = handle

        resp = await self._send_bluetooth_message_await_response(
            address,
            handle,
            req,
            BluetoothGATTReadResponse,
            timeout=timeout,
        )

        read_response = BluetoothGATTRead.from_pb(resp)

        return bytearray(read_response.data)

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
            assert self._connection is not None
            await self._connection.send_message(req)
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
        req = BluetoothGATTReadDescriptorRequest()
        req.address = address
        req.handle = handle

        resp = await self._send_bluetooth_message_await_response(
            address,
            handle,
            req,
            BluetoothGATTReadResponse,
            timeout=timeout,
        )

        read_response = BluetoothGATTRead.from_pb(resp)

        return bytearray(read_response.data)

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
            assert self._connection is not None
            await self._connection.send_message(req)
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
    ) -> Tuple[Callable[[], Coroutine[Any, Any, None]], Callable[[], None]]:
        """Start a notify session for a GATT characteristic.

        Returns two functions that can be used to stop the notify.

        The first function is a coroutine that can be awaited to stop the notify.

        The second function is a callback that can be called to remove the notify
        callbacks without stopping the notify session on the remote device, which
        should be used when the connection is lost.
        """

        await self._send_bluetooth_message_await_response(
            address,
            handle,
            BluetoothGATTNotifyRequest(address=address, handle=handle, enable=True),
            BluetoothGATTNotifyResponse,
        )

        def on_msg(msg: BluetoothGATTNotifyDataResponse) -> None:
            notify = BluetoothGATTRead.from_pb(msg)
            if address == notify.address and handle == notify.handle:
                on_bluetooth_gatt_notify(handle, bytearray(notify.data))

        assert self._connection is not None
        remove_callback = self._connection.add_message_callback(
            on_msg, (BluetoothGATTNotifyDataResponse,)
        )

        async def stop_notify() -> None:
            if self._connection is None:
                return

            remove_callback()

            self._check_authenticated()

            await self._connection.send_message(
                BluetoothGATTNotifyRequest(address=address, handle=handle, enable=False)
            )

        return stop_notify, remove_callback

    async def subscribe_home_assistant_states(
        self, on_state_sub: Callable[[str, Optional[str]], None]
    ) -> None:
        self._check_authenticated()

        def on_msg(msg: SubscribeHomeAssistantStateResponse) -> None:
            on_state_sub(msg.entity_id, msg.attribute)

        assert self._connection is not None
        await self._connection.send_message_callback_response(
            SubscribeHomeAssistantStatesRequest(),
            on_msg,
            (SubscribeHomeAssistantStateResponse,),
        )

    async def send_home_assistant_state(
        self, entity_id: str, attribute: Optional[str], state: str
    ) -> None:
        self._check_authenticated()

        assert self._connection is not None
        await self._connection.send_message(
            HomeAssistantStateResponse(
                entity_id=entity_id,
                state=state,
                attribute=attribute,
            )
        )

    async def cover_command(
        self,
        key: int,
        position: Optional[float] = None,
        tilt: Optional[float] = None,
        stop: bool = False,
    ) -> None:
        self._check_authenticated()

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
        assert self._connection is not None
        await self._connection.send_message(req)

    async def fan_command(
        self,
        key: int,
        state: Optional[bool] = None,
        speed: Optional[FanSpeed] = None,
        speed_level: Optional[int] = None,
        oscillating: Optional[bool] = None,
        direction: Optional[FanDirection] = None,
    ) -> None:
        self._check_authenticated()

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
        assert self._connection is not None
        await self._connection.send_message(req)

    async def light_command(
        self,
        key: int,
        state: Optional[bool] = None,
        brightness: Optional[float] = None,
        color_mode: Optional[int] = None,
        color_brightness: Optional[float] = None,
        rgb: Optional[Tuple[float, float, float]] = None,
        white: Optional[float] = None,
        color_temperature: Optional[float] = None,
        cold_white: Optional[float] = None,
        warm_white: Optional[float] = None,
        transition_length: Optional[float] = None,
        flash_length: Optional[float] = None,
        effect: Optional[str] = None,
    ) -> None:
        self._check_authenticated()

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
        assert self._connection is not None
        await self._connection.send_message(req)

    async def switch_command(self, key: int, state: bool) -> None:
        self._check_authenticated()

        req = SwitchCommandRequest()
        req.key = key
        req.state = state
        assert self._connection is not None
        await self._connection.send_message(req)

    async def climate_command(
        self,
        key: int,
        mode: Optional[ClimateMode] = None,
        target_temperature: Optional[float] = None,
        target_temperature_low: Optional[float] = None,
        target_temperature_high: Optional[float] = None,
        fan_mode: Optional[ClimateFanMode] = None,
        swing_mode: Optional[ClimateSwingMode] = None,
        custom_fan_mode: Optional[str] = None,
        preset: Optional[ClimatePreset] = None,
        custom_preset: Optional[str] = None,
    ) -> None:
        self._check_authenticated()

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
        assert self._connection is not None
        await self._connection.send_message(req)

    async def number_command(self, key: int, state: float) -> None:
        self._check_authenticated()

        req = NumberCommandRequest()
        req.key = key
        req.state = state
        assert self._connection is not None
        await self._connection.send_message(req)

    async def select_command(self, key: int, state: str) -> None:
        self._check_authenticated()

        req = SelectCommandRequest()
        req.key = key
        req.state = state
        assert self._connection is not None
        await self._connection.send_message(req)

    async def siren_command(
        self,
        key: int,
        state: Optional[bool] = None,
        tone: Optional[str] = None,
        volume: Optional[float] = None,
        duration: Optional[int] = None,
    ) -> None:
        self._check_authenticated()

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
        assert self._connection is not None
        await self._connection.send_message(req)

    async def button_command(self, key: int) -> None:
        self._check_authenticated()

        req = ButtonCommandRequest()
        req.key = key
        assert self._connection is not None
        await self._connection.send_message(req)

    async def lock_command(
        self,
        key: int,
        command: LockCommand,
        code: Optional[str] = None,
    ) -> None:
        self._check_authenticated()

        req = LockCommandRequest()
        req.key = key
        req.command = command
        if code is not None:
            req.code = code
        assert self._connection is not None
        await self._connection.send_message(req)

    async def media_player_command(
        self,
        key: int,
        *,
        command: Optional[MediaPlayerCommand] = None,
        volume: Optional[float] = None,
        media_url: Optional[str] = None,
    ) -> None:
        self._check_authenticated()

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
        assert self._connection is not None
        await self._connection.send_message(req)

    async def execute_service(
        self, service: UserService, data: ExecuteServiceDataType
    ) -> None:
        self._check_authenticated()

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
        assert self._connection is not None
        await self._connection.send_message(req)

    async def _request_image(
        self, *, single: bool = False, stream: bool = False
    ) -> None:
        req = CameraImageRequest()
        req.single = single
        req.stream = stream
        assert self._connection is not None
        await self._connection.send_message(req)

    async def request_single_image(self) -> None:
        await self._request_image(single=True)

    async def request_image_stream(self) -> None:
        await self._request_image(stream=True)

    @property
    def api_version(self) -> Optional[APIVersion]:
        if self._connection is None:
            return None
        return self._connection.api_version
