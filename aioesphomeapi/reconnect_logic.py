import asyncio
import logging
from typing import Awaitable, Callable, List, Optional

import zeroconf

from .client import APIClient
from .core import APIConnectionError

_LOGGER = logging.getLogger(__name__)

EXPECTED_DISCONNECT_COOLDOWN = 3.0


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
        on_disconnect: Callable[[], Awaitable[None]],
        zeroconf_instance: "zeroconf.Zeroconf",
        name: Optional[str] = None,
        on_connect_error: Optional[Callable[[Exception], Awaitable[None]]] = None,
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
        self._filter_alias: Optional[str] = None
        # Flag to check if the device is connected
        self._connected = False
        self._connected_lock = asyncio.Lock()
        self._is_stopped = True
        self._zc_listening = False
        # How many connect attempts have there been already, used for exponential wait time
        self._tries = 0
        # Event for tracking when logic should stop
        self._connect_task: Optional[asyncio.Task[None]] = None
        self._connect_timer: Optional[asyncio.TimerHandle] = None
        self._stop_task: Optional[asyncio.Task[None]] = None

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
        await self._on_disconnect_cb()

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
                "Can't connect to ESPHome API for %s: %s",
                self._log_name,
                err,
                # Print stacktrace if unhandled (not APIConnectionError)
                exc_info=not isinstance(err, APIConnectionError),
            )
            self._tries += 1
            return False
        _LOGGER.info("Successfully connected to %s", self._log_name)
        self._connected = True
        self._tries = 0
        await self._on_connect_cb()
        return True

    def _schedule_connect(self, delay: float) -> None:
        """Schedule a connect attempt."""
        self._cancel_connect()
        if not delay:
            self._call_connect_once()
            return
        self._connect_timer = self.loop.call_later(delay, self._call_connect_once)

    def _call_connect_once(self) -> None:
        """Call the connect logic once.

        Must only be called from _schedule_connect.
        """
        self._connect_task = asyncio.create_task(
            self._connect_once_or_reschedule(),
            name=f"{self._log_name}: aioesphomeapi connect",
        )

    def _cancel_connect(self) -> None:
        """Cancel the connect."""
        if self._connect_timer:
            self._connect_timer.cancel()
            self._connect_timer = None
        if self._connect_task:
            self._connect_task.cancel()
            self._connect_task = None

    async def _connect_once_or_reschedule(self) -> None:
        """Connect once or schedule connect.

        Must only be called from _call_connect_once
        """
        async with self._connected_lock:
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
        self._cancel_connect()
        async with self._connected_lock:
            self._is_stopped = True
            # Cancel again while holding the lock
            self._cancel_connect()
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
        zc: "zeroconf.Zeroconf",  # pylint: disable=unused-argument
        now: float,  # pylint: disable=unused-argument
        records: List["zeroconf.RecordUpdate"],
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
            if (
                not isinstance(record_update.new, zeroconf.DNSPointer)  # type: ignore[attr-defined]
                or record_update.new.alias != self._filter_alias
            ):
                continue

            # Tell connection logic to retry connection attempt now (even before connect timer finishes)
            _LOGGER.debug(
                "%s: Triggering connect because of received mDNS record %s",
                self._log_name,
                record_update.new,
            )
            self._stop_zc_listen()
            self._schedule_connect(0.0)
            return
