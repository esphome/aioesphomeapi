from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable
from typing import Callable

import zeroconf

from .client import APIClient
from .core import (
    APIConnectionError,
    InvalidAuthAPIError,
    InvalidEncryptionKeyAPIError,
    RequiresEncryptionAPIError,
)

_LOGGER = logging.getLogger(__name__)

EXPECTED_DISCONNECT_COOLDOWN = 5.0
MAXIMUM_BACKOFF_TRIES = 100
TYPE_PTR = 12


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
        self.name = name
        self._on_connect_cb = on_connect
        self._on_disconnect_cb = on_disconnect
        self._on_connect_error_cb = on_connect_error
        self._zc = zeroconf_instance
        self._filter_alias: str | None = None
        # Flag to check if the device is connected
        self._connected = False
        self._connected_lock = asyncio.Lock()
        self._is_stopped = True
        self._zc_listening = False
        # How many connect attempts have there been already, used for exponential wait time
        self._tries = 0
        # Event for tracking when logic should stop
        self._connect_task: asyncio.Task[None] | None = None
        self._connect_timer: asyncio.TimerHandle | None = None
        self._stop_task: asyncio.Task[None] | None = None

    @property
    def _log_name(self) -> str:
        if self.name is not None:
            return f"{self.name} @ {self._cli.address}"
        return self._cli.address

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

        async with self._connected_lock:
            self._connected = False

        wait = EXPECTED_DISCONNECT_COOLDOWN if expected_disconnect else 0
        # If we expected the disconnect we need
        # to cooldown before connecting in case the remote
        # is rebooting so we don't establish a connection right
        # before its about to reboot in the event we are too fast.
        self._schedule_connect(wait)

    async def _try_connect(self) -> bool:
        """Try connecting to the API client."""
        assert self._connected_lock.locked(), "connected_lock must be locked"
        try:
            await self._cli.connect(on_stop=self._on_disconnect, login=True)
        except Exception as err:  # pylint: disable=broad-except
            if self._on_connect_error_cb is not None:
                await self._on_connect_error_cb(err)
            level = logging.WARNING if self._tries == 0 else logging.DEBUG
            _LOGGER.log(
                level,
                "Can't connect to ESPHome API for %s: %s (%s)",
                self._log_name,
                err,
                type(err).__name__,
                # Print stacktrace if unhandled (not APIConnectionError)
                exc_info=not isinstance(err, APIConnectionError),
            )
            if isinstance(
                err,
                (
                    RequiresEncryptionAPIError,
                    InvalidEncryptionKeyAPIError,
                    InvalidAuthAPIError,
                ),
            ):
                # If we get an encryption or password error,
                # backoff for the maximum amount of time
                self._tries = MAXIMUM_BACKOFF_TRIES
            else:
                self._tries += 1
            return False
        _LOGGER.info("Successfully connected to %s", self._log_name)
        self._connected = True
        self._tries = 0
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
            self._stop_zc_listen()
            if self._connected or self._is_stopped:
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

    def stop_callback(self) -> None:
        """Stop the connect logic."""

        def _remove_stop_task(_fut: asyncio.Future[None]) -> None:
            """Remove the stop task from the connect loop.
            We need to do this because the asyncio does not hold
            a strong reference to the task, so it can be garbage
            collected unexpectedly.
            """
            self._stop_task = None

        self._stop_task = asyncio.create_task(
            self.stop(),
            name=f"{self._log_name}: aioesphomeapi reconnect_logic stop_callback",
        )
        self._stop_task.add_done_callback(_remove_stop_task)

    async def start(self) -> None:
        """Start the connecting logic background task."""
        if self.name:
            self._cli.set_cached_name_if_unset(self.name)
        async with self._connected_lock:
            self._is_stopped = False
            if self._connected:
                return
            self._tries = 0
            self._schedule_connect(0.0)

    async def stop(self) -> None:
        """Stop the connecting logic background task. Does not disconnect the client."""
        self._cancel_connect("Stopping")
        async with self._connected_lock:
            self._is_stopped = True
            # Cancel again while holding the lock
            self._cancel_connect("Stopping")
            self._stop_zc_listen()

    def _start_zc_listen(self) -> None:
        """Listen for mDNS records.

        This listener allows us to schedule a connect as soon as a
        received mDNS record indicates the node is up again.
        """
        if not self._zc_listening and self.name:
            _LOGGER.debug("Starting zeroconf listener for %s", self.name)
            self._filter_alias = f"{self.name}._esphomelib._tcp.local."
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
        if self._connected or self._is_stopped or self._filter_alias is None:
            return

        for record_update in records:
            # We only consider PTR records and match using the alias name
            new_record = record_update.new
            if (
                new_record.type != TYPE_PTR
                or new_record.alias != self._filter_alias  # type: ignore[attr-defined]
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
