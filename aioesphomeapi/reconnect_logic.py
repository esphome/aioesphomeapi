from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from enum import Enum
import logging
import time
from typing import Callable

import zeroconf
from zeroconf.const import (
    _TYPE_A as TYPE_A,
    _TYPE_AAAA as TYPE_AAAA,
    _TYPE_PTR as TYPE_PTR,
)

from .client import APIClient
from .core import (
    APIConnectionError,
    InvalidAuthAPIError,
    InvalidEncryptionKeyAPIError,
    RequiresEncryptionAPIError,
    UnhandledAPIConnectionError,
)
from .util import address_is_local, create_eager_task, host_is_name_part, is_ip_address
from .zeroconf import ZeroconfInstanceType

_LOGGER = logging.getLogger(__name__)

ADDRESS_RECORD_TYPES = {TYPE_A, TYPE_AAAA}

EXPECTED_DISCONNECT_COOLDOWN = 5.0
MAXIMUM_BACKOFF_TRIES = 100


class ReconnectLogicState(Enum):
    RESOLVING = 0
    CONNECTING = 1
    HANDSHAKING = 2
    READY = 3
    DISCONNECTED = 4


NOT_YET_CONNECTED_STATES = {
    ReconnectLogicState.DISCONNECTED,
    ReconnectLogicState.CONNECTING,
    ReconnectLogicState.RESOLVING,
}


AUTH_EXCEPTIONS = (
    RequiresEncryptionAPIError,
    InvalidEncryptionKeyAPIError,
    InvalidAuthAPIError,
)


class ReconnectLogic(zeroconf.RecordUpdateListener):
    """Reconnectiong logic handler for ESPHome config entries.

    Contains two reconnect strategies:
     - Connect with increasing time between connection attempts.
     - Listen to zeroconf mDNS records, if any records are found for this device, try reconnecting immediately.

    All methods in this class should be run inside the eventloop unless stated otherwise.
    """

    def __init__(
        self,
        *,
        client: APIClient,
        on_connect: Callable[[], Awaitable[None]],
        on_disconnect: Callable[[bool], Awaitable[None]],
        zeroconf_instance: ZeroconfInstanceType | None = None,
        name: str | None = None,
        on_connect_error: Callable[[Exception], Awaitable[None]] | None = None,
    ) -> None:
        """Initialize ReconnectingLogic.

        :param client: initialized :class:`APIClient` to reconnect for
        :param on_connect: Coroutine Function to call when connected.
        :param on_disconnect: Coroutine Function to call when disconnected.
        """
        self.loop = asyncio.get_running_loop()
        self._cli = client
        self.name: str | None = None
        self._is_ip_address = is_ip_address(name)
        if name:
            self.name = name
        elif host_is_name_part(client.address) or address_is_local(client.address):
            self.name = client.address.partition(".")[0]
        if self.name:
            self._cli.set_cached_name_if_unset(self.name)
        self._on_connect_cb = on_connect
        self._on_disconnect_cb = on_disconnect
        self._on_connect_error_cb = on_connect_error
        self._zeroconf_manager = client.zeroconf_manager
        if zeroconf_instance is not None:
            self._zeroconf_manager.set_instance(zeroconf_instance)
        self._ptr_alias: str | None = None
        self._a_name: str | None = None
        # Flag to check if the device is connected
        self._connection_state = ReconnectLogicState.DISCONNECTED
        self._accept_zeroconf_records: bool = True
        self._connected_lock = asyncio.Lock()
        self._is_stopped = True
        self._zc_listening = False
        # How many connect attempts have there been already, used for exponential wait time
        self._tries = 0
        # Event for tracking when logic should stop
        self._connect_task: asyncio.Task[None] | None = None
        self._connect_timer: asyncio.TimerHandle | None = None
        self._stop_task: asyncio.Task[None] | None = None

    async def _on_disconnect(self, expected_disconnect: bool) -> None:
        """Log and issue callbacks when disconnecting."""
        # This can happen often depending on WiFi signal strength.
        # So therefore all these connection warnings are logged
        # as infos. The "unavailable" logic will still trigger so the
        # user knows if the device is not connected.
        if expected_disconnect:
            # If we expected the disconnect we need
            # to cooldown before connecting in case the remote
            # is rebooting so we don't establish a connection right
            # before its about to reboot in the event we are too fast.
            disconnect_type = "expected"
            wait = EXPECTED_DISCONNECT_COOLDOWN
        else:
            disconnect_type = "unexpected"
            wait = 0

        _LOGGER.info(
            "Processing %s disconnect from ESPHome API for %s",
            disconnect_type,
            self._cli.log_name,
        )

        # Run disconnect hook
        async with self._connected_lock:
            self._async_set_connection_state_while_locked(
                ReconnectLogicState.DISCONNECTED
            )
            await self._on_disconnect_cb(expected_disconnect)

        if not self._is_stopped:
            self._schedule_connect(wait)

    def _async_set_connection_state_while_locked(
        self, state: ReconnectLogicState
    ) -> None:
        """Set the connection state while holding the lock."""
        assert self._connected_lock.locked(), "connected_lock must be locked"
        self._async_set_connection_state_without_lock(state)

    def _async_set_connection_state_without_lock(
        self, state: ReconnectLogicState
    ) -> None:
        """Set the connection state without holding the lock.

        This should only be used for setting the state to DISCONNECTED
        when the state is CONNECTING.
        """
        self._connection_state = state
        self._accept_zeroconf_records = state in NOT_YET_CONNECTED_STATES

    def _async_log_connection_error(self, err: Exception) -> None:
        """Log connection errors."""
        # UnhandledAPIConnectionError is a special case in client
        # for when the connection raises an exception that is not
        # handled by the client. This is usually a bug in the connection
        # code and should be logged as an error.
        is_handled_exception = not isinstance(
            err, UnhandledAPIConnectionError
        ) and isinstance(err, APIConnectionError)
        if not is_handled_exception:
            level = logging.ERROR
        elif self._tries == 0:
            level = logging.WARNING
        else:
            level = logging.DEBUG
        _LOGGER.log(
            level,
            "Can't connect to ESPHome API for %s: %s (%s)",
            self._cli.log_name,
            err,
            type(err).__name__,
            # Print stacktrace if unhandled
            exc_info=not is_handled_exception,
        )

    async def _try_connect(self) -> bool:
        """Try connecting to the API client."""
        self._async_set_connection_state_while_locked(ReconnectLogicState.RESOLVING)
        start_resolve_time = time.perf_counter()
        try:
            await self._cli.start_resolve_host(on_stop=self._on_disconnect)
        except Exception as err:  # pylint: disable=broad-except
            await self._handle_connection_failure(err)
            return False
        self._async_set_connection_state_while_locked(ReconnectLogicState.CONNECTING)
        start_connect_time = time.perf_counter()
        resolve_time = start_connect_time - start_resolve_time
        _LOGGER.info(
            "Successfully resolved %s in %0.3fs", self._cli.log_name, resolve_time
        )
        try:
            await self._cli.start_connection()
        except Exception as err:  # pylint: disable=broad-except
            await self._handle_connection_failure(err)
            return False
        finish_connect_time = time.perf_counter()
        connect_time = finish_connect_time - start_connect_time
        _LOGGER.info(
            "Successfully connected to %s in %0.3fs", self._cli.log_name, connect_time
        )
        self._stop_zc_listen()
        self._async_set_connection_state_while_locked(ReconnectLogicState.HANDSHAKING)
        try:
            await self._cli.finish_connection(login=True)
        except Exception as err:  # pylint: disable=broad-except
            await self._handle_connection_failure(err)
            return False
        self._tries = 0
        finish_handshake_time = time.perf_counter()
        handshake_time = finish_handshake_time - finish_connect_time
        _LOGGER.info(
            "Successful handshake with %s in %0.3fs", self._cli.log_name, handshake_time
        )
        self._async_set_connection_state_while_locked(ReconnectLogicState.READY)
        await self._on_connect_cb()
        return True

    async def _handle_connection_failure(self, err: Exception) -> None:
        """Handle a connection failure."""
        self._async_set_connection_state_while_locked(ReconnectLogicState.DISCONNECTED)
        if self._on_connect_error_cb is not None:
            await self._on_connect_error_cb(err)
        self._async_log_connection_error(err)
        if isinstance(err, AUTH_EXCEPTIONS):
            # If we get an encryption or password error,
            # backoff for the maximum amount of time
            self._tries = MAXIMUM_BACKOFF_TRIES
        else:
            self._tries += 1

    def _schedule_connect(self, delay: float) -> None:
        """Schedule a connect attempt."""
        if not delay:
            self._call_connect_once()
            return
        _LOGGER.debug("Scheduling new connect attempt in %.2f seconds", delay)
        self._cancel_connect_timer()
        self._connect_timer = self.loop.call_at(
            self.loop.time() + delay, self._call_connect_once
        )

    def _call_connect_once(self) -> None:
        """Call the connect logic once.

        Must only be called from _schedule_connect.
        """
        if self._connect_task and not self._connect_task.done():
            if self._connection_state != ReconnectLogicState.CONNECTING:
                # Connection state is far enough along that we should
                # not restart the connect task.
                #
                # Zeroconf triggering scenarios:
                # - RESOLVING state: Don't cancel, the resolve task will complete immediately
                #   since it's waiting for the same records zeroconf is delivering
                # - CONNECTING state: Cancel and restart to use potentially updated connection info
                # - HANDSHAKING state or later: Don't cancel, too far along in the process
                _LOGGER.debug(
                    "%s: Not cancelling existing connect task as its already %s!",
                    self._cli.log_name,
                    self._connection_state,
                )
                return
            _LOGGER.debug(
                "%s: Cancelling existing connect task with state %s, to try again now!",
                self._cli.log_name,
                self._connection_state,
            )
            self._cancel_connect_task("Scheduling new connect attempt")
            self._async_set_connection_state_without_lock(
                ReconnectLogicState.DISCONNECTED
            )

        self._connect_task = create_eager_task(
            self._connect_once_or_reschedule(),
            name=f"{self._cli.log_name}: aioesphomeapi connect",
        )

    def _cancel_connect_timer(self) -> None:
        """Cancel the connect timer."""
        if self._connect_timer:
            self._connect_timer.cancel()
            self._connect_timer = None

    def _cancel_connect_task(self, msg: str) -> None:
        """Cancel the connect task."""
        if self._connect_task:
            self._connect_task.cancel(msg)
            self._connect_task = None

    def _cancel_connect(self, msg: str) -> None:
        """Cancel the connect."""
        self._cancel_connect_timer()
        self._cancel_connect_task(msg)

    async def _connect_once_or_reschedule(self) -> None:
        """Connect once or schedule connect.

        Must only be called from _call_connect_once
        """
        _LOGGER.debug("Trying to connect to %s", self._cli.log_name)
        async with self._connected_lock:
            _LOGGER.debug("Connected lock acquired for %s", self._cli.log_name)
            if (
                self._connection_state != ReconnectLogicState.DISCONNECTED
                or self._is_stopped
            ):
                return
            self._start_zc_listen()
            if await self._try_connect():
                return
            tries = min(self._tries, 10)  # prevent OverflowError
            wait_time = round(min(1.8**tries, 60.0))
            if tries == 1:
                _LOGGER.info(
                    "Trying to connect to %s in the background", self._cli.log_name
                )
            _LOGGER.debug("Retrying %s in %.2f seconds", self._cli.log_name, wait_time)
            self._schedule_connect(wait_time)

    def _remove_stop_task(self, _fut: asyncio.Future[None]) -> None:
        """Remove the stop task from the connect loop.
        We need to do this because the asyncio does not hold
        a strong reference to the task, so it can be garbage
        collected unexpectedly.
        """
        self._stop_task = None

    def stop_callback(self) -> None:
        """Stop the connect logic."""
        self._stop_task = create_eager_task(
            self.stop(),
            name=f"{self._cli.log_name}: aioesphomeapi reconnect_logic stop_callback",
        )
        self._stop_task.add_done_callback(self._remove_stop_task)

    async def start(self) -> None:
        """Start the connecting logic background task."""
        async with self._connected_lock:
            self._is_stopped = False
            if self._connection_state != ReconnectLogicState.DISCONNECTED:
                return
            self._tries = 0
            self._schedule_connect(0.0)

    async def stop(self) -> None:
        """Stop the connecting logic background task. Does not disconnect the client."""
        if self._connection_state in NOT_YET_CONNECTED_STATES:
            # If we are still establishing a connection, we can safely
            # cancel the connect task here, otherwise we need to wait
            # for the connect task to finish so we can gracefully
            # disconnect.
            self._cancel_connect("Stopping")

        async with self._connected_lock:
            self._is_stopped = True
            # Cancel again while holding the lock
            self._cancel_connect("Stopping")
            self._stop_zc_listen()
            self._async_set_connection_state_while_locked(
                ReconnectLogicState.DISCONNECTED
            )

        await self._zeroconf_manager.async_close()

    def _start_zc_listen(self) -> None:
        """Listen for mDNS records.

        This listener allows us to schedule a connect as soon as a
        received mDNS record indicates the node is up again.
        """
        if not self._zc_listening and self.name and not self._is_ip_address:
            _LOGGER.debug("Starting zeroconf listener for %s", self.name)
            self._ptr_alias = f"{self.name}._esphomelib._tcp.local."
            self._a_name = f"{self.name}.local."
            self._zeroconf_manager.get_async_zeroconf().zeroconf.async_add_listener(
                self, None
            )
            self._zc_listening = True

    def _stop_zc_listen(self) -> None:
        """Stop listening for zeroconf updates."""
        if self._zc_listening:
            _LOGGER.debug("Removing zeroconf listener for %s", self.name)
            self._zeroconf_manager.get_async_zeroconf().zeroconf.async_remove_listener(
                self
            )
            self._zc_listening = False

    def _connect_from_zeroconf(self) -> None:
        """Connect from zeroconf."""
        self._stop_zc_listen()
        self._schedule_connect(0.0)

    def async_update_records(
        self,
        zc: zeroconf.Zeroconf,  # pylint: disable=unused-argument
        now: float,  # pylint: disable=unused-argument
        records: list[zeroconf.RecordUpdate],
    ) -> None:
        """Listen to zeroconf updated mDNS records. This must be called from the eventloop.

        This is a mDNS record from the device and could mean it just woke up.
        """
        # Check if already connected, no lock needed for this access and
        # bail if either the already stopped or we haven't received device info yet
        if not self._accept_zeroconf_records or self._is_stopped:
            return

        for record_update in records:
            # We only consider A, AAAA, and PTR records and match using the alias name
            new_record = record_update.new
            if not (
                (new_record.type == TYPE_PTR and new_record.alias == self._ptr_alias)  # type: ignore[attr-defined]
                or (
                    new_record.type in ADDRESS_RECORD_TYPES
                    and new_record.name == self._a_name
                )
            ):
                continue

            # Tell connection logic to retry connection attempt now (even before connect timer finishes)
            _LOGGER.debug(
                "%s: Triggering connect because of received mDNS record %s",
                self._cli.log_name,
                record_update.new,
            )
            #
            # If we scheduled the connect attempt immediately, the listener could fire
            # again before the connect attempt and we cancel and reschedule the connect
            # attempt again.
            #
            self._connect_from_zeroconf()
            self._accept_zeroconf_records = False
            return
