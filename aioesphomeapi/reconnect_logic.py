from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable
from enum import Enum
from typing import Callable

import zeroconf
from zeroconf.const import _TYPE_A as TYPE_A
from zeroconf.const import _TYPE_PTR as TYPE_PTR

from .client import APIClient
from .core import (
    APIConnectionError,
    InvalidAuthAPIError,
    InvalidEncryptionKeyAPIError,
    RequiresEncryptionAPIError,
    UnhandledAPIConnectionError,
)

_LOGGER = logging.getLogger(__name__)

EXPECTED_DISCONNECT_COOLDOWN = 5.0
MAXIMUM_BACKOFF_TRIES = 100


class ReconnectLogicState(Enum):
    CONNECTING = 0
    HANDSHAKING = 1
    READY = 2
    DISCONNECTED = 3


NOT_YET_CONNECTED_STATES = {
    ReconnectLogicState.DISCONNECTED,
    ReconnectLogicState.CONNECTING,
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
        zeroconf_instance: zeroconf.Zeroconf,
        name: str | None = None,
        on_connect_error: Callable[[Exception], Awaitable[None]] | None = None,
    ) -> None:
        """Initialize ReconnectingLogic.

        :param client: initialized :class:`APIClient` to reconnect for
        :param on_connect: Coroutine Function to call when connected.
        :param on_disconnect: Coroutine Function to call when disconnected.
        """
        self.loop = asyncio.get_event_loop()
        self._cli = client
        self.name: str | None
        if client.address.endswith(".local"):
            self.name = client.address[:-6]
            self._log_name = self.name
        elif name:
            self.name = name
            self._log_name = f"{name} @ {self._cli.address}"
            self._cli.set_cached_name_if_unset(name)
        else:
            self.name = None
            self._log_name = client.address
        self._on_connect_cb = on_connect
        self._on_disconnect_cb = on_disconnect
        self._on_connect_error_cb = on_connect_error
        self._zc = zeroconf_instance
        self._ptr_alias: str | None = None
        self._a_name: str | None = None
        # Flag to check if the device is connected
        self._connection_state = ReconnectLogicState.DISCONNECTED
        self._accept_zeroconf_records = True
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
        if self._is_stopped:
            return
        # This can happen often depending on WiFi signal strength.
        # So therefore all these connection warnings are logged
        # as infos. The "unavailable" logic will still trigger so the
        # user knows if the device is not connected.
        disconnect_type = "expected" if expected_disconnect else "unexpected"
        _LOGGER.info(
            "Processing %s disconnect from ESPHome API for %s",
            disconnect_type,
            self._log_name,
        )

        # Run disconnect hook
        await self._on_disconnect_cb(expected_disconnect)

        await self._async_set_connection_state(ReconnectLogicState.DISCONNECTED)

        wait = EXPECTED_DISCONNECT_COOLDOWN if expected_disconnect else 0
        # If we expected the disconnect we need
        # to cooldown before connecting in case the remote
        # is rebooting so we don't establish a connection right
        # before its about to reboot in the event we are too fast.
        self._schedule_connect(wait)

    async def _async_set_connection_state(self, state: ReconnectLogicState) -> None:
        """Set the connection state."""
        async with self._connected_lock:
            self._async_set_connection_state_while_locked(state)

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
            self._log_name,
            err,
            type(err).__name__,
            # Print stacktrace if unhandled
            exc_info=not is_handled_exception,
        )

    async def _try_connect(self) -> bool:
        """Try connecting to the API client."""
        self._async_set_connection_state_while_locked(ReconnectLogicState.CONNECTING)
        start_connect_time = time.perf_counter()
        try:
            await self._cli.start_connection(on_stop=self._on_disconnect)
        except Exception as err:  # pylint: disable=broad-except
            self._async_set_connection_state_while_locked(
                ReconnectLogicState.DISCONNECTED
            )
            if self._on_connect_error_cb is not None:
                await self._on_connect_error_cb(err)
            self._async_log_connection_error(err)
            self._tries += 1
            return False
        finish_connect_time = time.perf_counter()
        connect_time = finish_connect_time - start_connect_time
        _LOGGER.info(
            "Successfully connected to %s in %0.3fs", self._log_name, connect_time
        )
        self._stop_zc_listen()
        self._async_set_connection_state_while_locked(ReconnectLogicState.HANDSHAKING)
        try:
            await self._cli.finish_connection(login=True)
        except Exception as err:  # pylint: disable=broad-except
            self._async_set_connection_state_while_locked(
                ReconnectLogicState.DISCONNECTED
            )
            if self._on_connect_error_cb is not None:
                await self._on_connect_error_cb(err)
            self._async_log_connection_error(err)
            if isinstance(err, AUTH_EXCEPTIONS):
                # If we get an encryption or password error,
                # backoff for the maximum amount of time
                self._tries = MAXIMUM_BACKOFF_TRIES
            else:
                self._tries += 1
            return False
        self._tries = 0
        finish_handshake_time = time.perf_counter()
        handshake_time = finish_handshake_time - finish_connect_time
        _LOGGER.info(
            "Successful handshake with %s in %0.3fs", self._log_name, handshake_time
        )
        self._async_set_connection_state_while_locked(ReconnectLogicState.READY)
        await self._on_connect_cb()
        return True

    def _schedule_connect(self, delay: float) -> None:
        """Schedule a connect attempt."""
        self._cancel_connect("Scheduling new connect attempt")
        if not delay:
            self._call_connect_once()
            return
        _LOGGER.debug("Scheduling new connect attempt in %f seconds", delay)
        self._connect_timer = self.loop.call_at(
            self.loop.time() + delay, self._call_connect_once
        )

    def _call_connect_once(self) -> None:
        """Call the connect logic once.

        Must only be called from _schedule_connect.
        """
        if self._connect_task:
            if self._connection_state != ReconnectLogicState.CONNECTING:
                # Connection state is far enough along that we should
                # not restart the connect task
                return
            _LOGGER.debug(
                "%s: Cancelling existing connect task, to try again now!",
                self._log_name,
            )
            self._connect_task.cancel("Scheduling new connect attempt")
            self._connect_task = None
            self._async_set_connection_state_without_lock(
                ReconnectLogicState.DISCONNECTED
            )

        self._connect_task = asyncio.create_task(
            self._connect_once_or_reschedule(),
            name=f"{self._log_name}: aioesphomeapi connect",
        )

    def _cancel_connect(self, msg: str) -> None:
        """Cancel the connect."""
        if self._connect_timer:
            self._connect_timer.cancel()
            self._connect_timer = None
        if self._connect_task:
            self._connect_task.cancel(msg)
            self._connect_task = None

    async def _connect_once_or_reschedule(self) -> None:
        """Connect once or schedule connect.

        Must only be called from _call_connect_once
        """
        _LOGGER.debug("Trying to connect to %s", self._log_name)
        async with self._connected_lock:
            _LOGGER.debug("Connected lock acquired for %s", self._log_name)
            if (
                self._connection_state != ReconnectLogicState.DISCONNECTED
                or self._is_stopped
            ):
                return
            if await self._try_connect():
                return
            tries = min(self._tries, 10)  # prevent OverflowError
            wait_time = int(round(min(1.8**tries, 60.0)))
            if tries == 1:
                _LOGGER.info(
                    "Trying to connect to %s in the background", self._log_name
                )
            _LOGGER.debug("Retrying %s in %d seconds", self._log_name, wait_time)
            if wait_time:
                # If we are waiting, start listening for mDNS records
                self._start_zc_listen()
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
        self._stop_task = asyncio.create_task(
            self.stop(),
            name=f"{self._log_name}: aioesphomeapi reconnect_logic stop_callback",
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

    def _start_zc_listen(self) -> None:
        """Listen for mDNS records.

        This listener allows us to schedule a connect as soon as a
        received mDNS record indicates the node is up again.
        """
        if not self._zc_listening and self.name:
            _LOGGER.debug("Starting zeroconf listener for %s", self.name)
            self._ptr_alias = f"{self.name}._esphomelib._tcp.local."
            self._a_name = f"{self.name}.local."
            self._zc.async_add_listener(self, None)
            self._zc_listening = True

    def _stop_zc_listen(self) -> None:
        """Stop listening for zeroconf updates."""
        if self._zc_listening:
            _LOGGER.debug("Removing zeroconf listener for %s", self.name)
            self._zc.async_remove_listener(self)
            self._zc_listening = False

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
            # We only consider PTR records and match using the alias name
            new_record = record_update.new
            if not (
                (new_record.type == TYPE_PTR and new_record.alias == self._ptr_alias)  # type: ignore[attr-defined]
                or (new_record.type == TYPE_A and new_record.name == self._a_name)
            ):
                continue

            # Tell connection logic to retry connection attempt now (even before connect timer finishes)
            _LOGGER.debug(
                "%s: Triggering connect because of received mDNS record %s",
                self._log_name,
                record_update.new,
            )
            # We can't stop the zeroconf listener here because we are in the middle of
            # a zeroconf callback which is iterating the listeners.
            #
            # So we schedule a stop for the next event loop iteration.
            self.loop.call_soon(self._stop_zc_listen)
            self._schedule_connect(0.0)
            return
