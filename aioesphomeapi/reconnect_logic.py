import asyncio
import logging
from typing import Awaitable, Callable, List, Optional

import zeroconf

from .client import APIClient
from .core import APIConnectionError

_LOGGER = logging.getLogger(__name__)


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
        self._cli = client
        self.name = name
        self._on_connect_cb = on_connect
        self._on_disconnect_cb = on_disconnect
        self._on_connect_error_cb = on_connect_error
        self._zc = zeroconf_instance
        # Flag to check if the device is connected
        self._connected = True
        self._connected_lock = asyncio.Lock()
        self._zc_lock = asyncio.Lock()
        self._zc_listening = False
        # Event the different strategies use for issuing a reconnect attempt.
        self._reconnect_event = asyncio.Event()
        # The task containing the infinite reconnect loop while running
        self._loop_task: Optional[asyncio.Task[None]] = None
        # How many reconnect attempts have there been already, used for exponential wait time
        self._tries = 0
        self._tries_lock = asyncio.Lock()
        # Track the wait task to cancel it on shutdown
        self._wait_task: Optional[asyncio.Task[None]] = None
        self._wait_task_lock = asyncio.Lock()
        # Event for tracking when logic should stop
        self._stop_event = asyncio.Event()

    @property
    def _is_stopped(self) -> bool:
        return self._stop_event.is_set()

    @property
    def _log_name(self) -> str:
        if self.name is not None:
            return f"{self.name} @ {self._cli.address}"
        return self._cli.address

    async def _on_disconnect(self) -> None:
        """Log and issue callbacks when disconnecting."""
        if self._is_stopped:
            return
        # This can happen often depending on WiFi signal strength.
        # So therefore all these connection warnings are logged
        # as infos. The "unavailable" logic will still trigger so the
        # user knows if the device is not connected.
        _LOGGER.info("Disconnected from ESPHome API for %s", self._log_name)

        # Run disconnect hook
        await self._on_disconnect_cb()
        await self._start_zc_listen()

        # Reset tries
        async with self._tries_lock:
            self._tries = 0
        # Connected needs to be reset before the reconnect event (opposite order of check)
        async with self._connected_lock:
            self._connected = False
        self._reconnect_event.set()

    async def _wait_and_start_reconnect(self) -> None:
        """Wait for exponentially increasing time to issue next reconnect event."""
        async with self._tries_lock:
            tries = self._tries
        # If not first re-try, wait and print message
        # Cap wait time at 1 minute. This is because while working on the
        # device (e.g. soldering stuff), users don't want to have to wait
        # a long time for their device to show up in HA again (this was
        # mentioned a lot in early feedback)
        tries = min(tries, 10)  # prevent OverflowError
        wait_time = int(round(min(1.8**tries, 60.0)))
        if tries == 1:
            _LOGGER.info("Trying to reconnect to %s in the background", self._log_name)
        _LOGGER.debug("Retrying %s in %d seconds", self._log_name, wait_time)
        await asyncio.sleep(wait_time)
        async with self._wait_task_lock:
            self._wait_task = None
        self._reconnect_event.set()

    async def _try_connect(self) -> None:
        """Try connecting to the API client."""
        async with self._tries_lock:
            tries = self._tries
            self._tries += 1

        try:
            await self._cli.connect(on_stop=self._on_disconnect, login=True)
        except Exception as err:  # pylint: disable=broad-except
            if self._on_connect_error_cb is not None:
                await self._on_connect_error_cb(err)
            level = logging.WARNING if tries == 0 else logging.DEBUG
            _LOGGER.log(
                level,
                "Can't connect to ESPHome API for %s: %s",
                self._log_name,
                err,
                # Print stacktrace if unhandled (not APIConnectionError)
                exc_info=not isinstance(err, APIConnectionError),
            )
            await self._start_zc_listen()
            # Schedule re-connect in event loop in order not to delay HA
            # startup. First connect is scheduled in tracked tasks.
            async with self._wait_task_lock:
                # Allow only one wait task at a time
                # can happen if mDNS record received while waiting, then use existing wait task
                if self._wait_task is not None:
                    return

                self._wait_task = asyncio.create_task(self._wait_and_start_reconnect())
        else:
            _LOGGER.info("Successfully connected to %s", self._log_name)
            async with self._tries_lock:
                self._tries = 0
            async with self._connected_lock:
                self._connected = True
            await self._stop_zc_listen()
            await self._on_connect_cb()

    async def _reconnect_once(self) -> None:
        # Wait and clear reconnection event
        await self._reconnect_event.wait()
        self._reconnect_event.clear()

        # If in connected state, do not try to connect again.
        async with self._connected_lock:
            if self._connected:
                return

        if self._is_stopped:
            return

        await self._try_connect()

    async def _reconnect_loop(self) -> None:
        while True:
            try:
                await self._reconnect_once()
            except asyncio.CancelledError:  # pylint: disable=try-except-raise
                raise
            except Exception:  # pylint: disable=broad-except
                _LOGGER.error(
                    "Caught exception while reconnecting to %s",
                    self._log_name,
                    exc_info=True,
                )

    async def start(self) -> None:
        """Start the reconnecting logic background task."""
        # Create reconnection loop outside of HA's tracked tasks in order
        # not to delay startup.
        self._loop_task = asyncio.create_task(self._reconnect_loop())

        async with self._connected_lock:
            self._connected = False
        self._reconnect_event.set()

    async def stop(self) -> None:
        """Stop the reconnecting logic background task. Does not disconnect the client."""
        if self._loop_task is not None:
            self._loop_task.cancel()
            self._loop_task = None
        async with self._wait_task_lock:
            if self._wait_task is not None:
                self._wait_task.cancel()
            self._wait_task = None
        await self._stop_zc_listen()

    def stop_callback(self) -> None:
        asyncio.create_task(self.stop())

    async def _start_zc_listen(self) -> None:
        """Listen for mDNS records.

        This listener allows us to schedule a reconnect as soon as a
        received mDNS record indicates the node is up again.
        """
        async with self._zc_lock:
            if not self._zc_listening:
                self._zc.async_add_listener(self, None)
                self._zc_listening = True

    async def _stop_zc_listen(self) -> None:
        """Stop listening for zeroconf updates."""
        async with self._zc_lock:
            if self._zc_listening:
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
        if (
            self._connected
            or self._reconnect_event.is_set()
            or self._is_stopped
            or self.name is None
        ):
            return

        filter_alias = f"{self.name}._esphomelib._tcp.local."

        for record_update in records:
            # We only consider PTR records and match using the alias name
            if (
                not isinstance(record_update.new, zeroconf.DNSPointer)  # type: ignore[attr-defined]
                or record_update.new.alias != filter_alias
            ):
                continue

            # Tell reconnection logic to retry connection attempt now (even before reconnect timer finishes)
            _LOGGER.debug(
                "%s: Triggering reconnect because of received mDNS record %s",
                self._log_name,
                record_update.new,
            )
            self._reconnect_event.set()
            return
