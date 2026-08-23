from __future__ import annotations

import asyncio
from enum import Enum
import logging
import time
from typing import TYPE_CHECKING

from .core import (
    APIConnectionCancelledError,
    APIConnectionError,
    EncryptionPlaintextAPIError,
    InvalidAuthAPIError,
    InvalidEncryptionKeyAPIError,
    RequiresEncryptionAPIError,
    UnhandledAPIConnectionError,
)
from .util import address_is_local, create_eager_task, host_is_name_part, is_ip_address

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from zeroconf import RecordUpdate, Zeroconf

    from ._zc_listener import ReconnectRecordUpdateListener
    from .client import APIClient
    from .zeroconf import ZeroconfInstanceType

_LOGGER = logging.getLogger(__name__)

# DNS record type codes (RFC 1035/3596), duplicated from zeroconf.const
# (pinned in tests) so this module does not import zeroconf at load time.
TYPE_A = 1
TYPE_PTR = 12
TYPE_AAAA = 28

ADDRESS_RECORD_TYPES = {TYPE_A, TYPE_AAAA}

# Connects that land within this window never load the zeroconf stack; an
# attempt still in flight when it fires gets the listener so a device that
# came online mid-attempt is woken by its boot announcement.
ZC_LISTEN_DELAY = 2.0

_zc_listener_cache: list[type[ReconnectRecordUpdateListener]] = []


def _import_zc_listener() -> type[ReconnectRecordUpdateListener]:
    # Preload zeroconf.asyncio too; start() needs it via get_async_zeroconf
    # and it is not pulled in by the top-level zeroconf import.
    import zeroconf.asyncio  # noqa: F401, PLC0415

    from ._zc_listener import ReconnectRecordUpdateListener  # noqa: PLC0415

    if not _zc_listener_cache:
        _zc_listener_cache.append(ReconnectRecordUpdateListener)
    return ReconnectRecordUpdateListener


EXPECTED_DISCONNECT_COOLDOWN = 5.0
MAXIMUM_BACKOFF_TRIES = 100
MAXIMUM_BACKOFF = 60.0
# Deep-sleep devices are only awake for a short window; a lost boot-announce must
# not leave a reconnect waiting out the full backoff past that window.
DEEP_SLEEP_MAXIMUM_BACKOFF = 15.0


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


class ZeroconfWake:
    """Deferred mDNS listener that wakes a reconnect attempt when its device announces."""

    def __init__(
        self,
        client: APIClient,
        name: str | None,
        can_kick: Callable[[], bool],
        on_wake: Callable[[], None],
    ) -> None:
        """Initialize the wake listener; can_kick gates records, on_wake kicks a connect."""
        self._loop = asyncio.get_running_loop()
        self._client = client
        self._name = name
        self._eligible = bool(name) and not is_ip_address(name)
        self._can_kick = can_kick
        self._on_wake = on_wake
        self._warned = False
        # RFC 6762 §16 / RFC 4343: mDNS labels are case-insensitive.
        # Lowercase the match keys here and the incoming records in
        # async_update_records so a device advertising mixed-case labels
        # still triggers the fast reconnect instead of falling back to
        # exponential backoff.
        self._ptr_alias: str | None = None
        self._a_name: str | None = None
        if self._eligible:
            self._ptr_alias = f"{name}._esphomelib._tcp.local.".lower()
            self._a_name = f"{name}.local.".lower()
        self._listening = False
        self._listener: ReconnectRecordUpdateListener | None = None
        self._timer: asyncio.TimerHandle | None = None
        self._start_task: asyncio.Task[None] | None = None
        # One-shot gate: a connect attempt is only kicked once per record burst.
        self._accept_records = True

    def reopen(self) -> None:
        """Allow the next matching mDNS record to kick a connect again."""
        self._accept_records = True

    def arm(self) -> None:
        """Arm the delayed listener start for a connect attempt."""
        if self._startable() and self._timer is None:
            self._timer = self._loop.call_later(ZC_LISTEN_DELAY, self.start_soon)

    def start_soon(self) -> None:
        """Start the listener via a task so the cold import stays off the loop."""
        self._cancel_timer()
        if self._startable():
            self._start_task = create_eager_task(
                self._async_start(),
                name=f"{self._client.log_name}: aioesphomeapi start zc listen",
            )
            self._start_task.add_done_callback(self._remove_start_task)

    def start(self) -> None:
        """Listen for mDNS records.

        This listener allows us to schedule a connect as soon as a
        received mDNS record indicates the node is up again. Failures
        to start the zeroconf stack (e.g. port 5353 already bound on
        BSD-derived systems running avahi) must not prevent the
        connect attempt; the listener is a reconnect-speed
        optimisation, not a requirement for connecting.
        """
        if not self._listening and self._eligible:
            _LOGGER.debug("Starting zeroconf listener for %s", self._name)
            try:
                if self._listener is None:
                    self._listener = _import_zc_listener()(self)
                async_zc = self._client.zeroconf_manager.get_async_zeroconf()
                async_zc.zeroconf.async_add_listener(self._listener, None)
            except Exception as err:  # noqa: BLE001  # pylint: disable=broad-except
                # WARNING once per instance, DEBUG after, so a broken
                # zeroconf stack is visible without spamming every retry.
                _LOGGER.log(
                    logging.DEBUG if self._warned else logging.WARNING,
                    "Could not start zeroconf listener for %s: %s (%s); "
                    "continuing without mDNS-triggered reconnects",
                    self._client.log_name,
                    err,
                    type(err).__name__,
                )
                self._warned = True
                return
            self._listening = True

    def stop(self) -> None:
        """Stop listening for zeroconf updates."""
        self._cancel_timer()
        if self._start_task:
            self._start_task.cancel()
            self._start_task = None
        if self._listening:
            _LOGGER.debug("Removing zeroconf listener for %s", self._name)
            if TYPE_CHECKING:
                assert self._listener is not None
            zc = self._client.zeroconf_manager.get_async_zeroconf().zeroconf
            zc.async_remove_listener(self._listener)
            self._listening = False

    def async_update_records(
        self,
        zc: Zeroconf,  # noqa: ARG002 # pylint: disable=unused-argument
        now: float,  # noqa: ARG002 # pylint: disable=unused-argument
        records: list[RecordUpdate],
    ) -> None:
        """Handle updated mDNS records. This must be called from the eventloop.

        This is a mDNS record from the device and could mean it just woke up.
        """
        # Bail if the current attempt has already been kicked by a previous
        # mDNS record (one-shot gate) or if a kick could no longer help
        # (stopped, or past the point where a restart matters).
        if not self._accept_records or not self._can_kick():
            return

        for record_update in records:
            # We only consider A, AAAA, and PTR records and match using the alias name
            new_record = record_update.new
            if not (
                (
                    new_record.type == TYPE_PTR
                    and new_record.alias.lower() == self._ptr_alias  # type: ignore[attr-defined]
                )
                or (
                    new_record.type in ADDRESS_RECORD_TYPES
                    and new_record.name.lower() == self._a_name
                )
            ):
                continue

            # Tell connection logic to retry connection attempt now (even before connect timer finishes)
            _LOGGER.debug(
                "%s: Triggering connect because of received mDNS record %s",
                self._client.log_name,
                record_update.new,
            )
            #
            # If we scheduled the connect attempt immediately, the listener could fire
            # again before the connect attempt and we cancel and reschedule the connect
            # attempt again.
            #
            self.stop()
            self._on_wake()
            self._accept_records = False
            return

    async def _async_start(self) -> None:
        """Import the listener off the event loop, then start listening."""
        if not _zc_listener_cache:
            try:
                await self._loop.run_in_executor(None, _import_zc_listener)
            except Exception as err:  # noqa: BLE001  # pylint: disable=broad-except
                # start() retries the import inline and logs if still failing.
                _LOGGER.debug(
                    "%s: off-loop zc listener import failed: %s",
                    self._client.log_name,
                    err,
                )
        if self._can_kick():
            self.start()

    def _startable(self) -> bool:
        """Return True when the listener may be armed or started."""
        return (
            self._eligible
            and not self._listening
            and (self._start_task is None or self._start_task.done())
        )

    def _cancel_timer(self) -> None:
        """Cancel the delayed listener start timer."""
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def _remove_start_task(self, fut: asyncio.Future[None]) -> None:
        if self._start_task is fut:
            self._start_task = None


class ReconnectLogic:
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
        allow_plaintext_fallback: bool = False,
    ) -> None:
        """Initialize ReconnectingLogic.

        :param client: initialized :class:`APIClient` to reconnect for
        :param on_connect: Coroutine Function to call when connected.
        :param on_disconnect: Coroutine Function to call when disconnected.
        :param allow_plaintext_fallback: If True and the client has a noise
            PSK configured, downgrade to plaintext (and log a warning) when
            the device responds with the plaintext protocol marker, instead
            of failing repeatedly. Defaults to False so callers must opt in.

            This is a security downgrade: an attacker on the network can
            impersonate the device in plaintext and strip encryption. Only
            enable it for connections that are read-only from the client's
            side — e.g. the logger stream, which only receives data from
            the device and never sends commands or secrets. Do not enable
            it for Home Assistant or any integration that issues commands
            to the device.
        """
        self.loop = asyncio.get_running_loop()
        self._cli = client
        self.name: str | None = None
        if name:
            self.name = name
        elif host_is_name_part(client.address) or address_is_local(client.address):
            self.name = client.address.partition(".")[0]
        if self.name:
            self._cli.set_cached_name_if_unset(self.name)
        # Caps the reconnect backoff so a short awake window is not missed. A
        # consumer may seed it before the first connect as a bootstrap hint
        # (e.g. from persisted DeviceInfo, so a restart caps from the first
        # attempt); each successful connect then refreshes it from the fetched
        # DeviceInfo.has_deep_sleep (see _try_connect), so device_info wins and
        # it self-heals.
        self.deep_sleep: bool = False
        self._on_connect_cb = on_connect
        self._on_disconnect_cb = on_disconnect
        self._on_connect_error_cb = on_connect_error
        self._allow_plaintext_fallback = allow_plaintext_fallback
        self._zeroconf_manager = client.zeroconf_manager
        if zeroconf_instance is not None:
            self._zeroconf_manager.set_instance(zeroconf_instance)
        # Flag to check if the device is connected
        self._connection_state = ReconnectLogicState.DISCONNECTED
        self._connected_lock = asyncio.Lock()
        self._is_stopped = True
        self._zc_wake = ZeroconfWake(
            client,
            self.name,
            self._zc_can_kick,
            self._connect_from_zeroconf,
        )
        # How many connect attempts have there been already, used for exponential wait time
        self._tries = 0
        # Event for tracking when logic should stop
        self._connect_task: asyncio.Task[None] | None = None
        self._connect_timer: asyncio.TimerHandle | None = None
        self._stop_task: asyncio.Task[None] | None = None
        self._unsub_addresses_changed: Callable[[], None] | None = None

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
            # The previous session ended — allow the next mDNS record to
            # kick a fresh connect attempt early.
            self._zc_wake.reopen()
            await self._on_disconnect_cb(expected_disconnect)

        if not self._is_stopped:
            self._schedule_connect(wait)

    def _async_set_connection_state_while_locked(
        self, state: ReconnectLogicState
    ) -> None:
        """Set the connection state while holding the lock."""
        assert self._connected_lock.locked(), "connected_lock must be locked"  # noqa: S101  # precondition
        self._async_set_connection_state_without_lock(state)

    def _async_set_connection_state_without_lock(
        self, state: ReconnectLogicState
    ) -> None:
        """Set the connection state without holding the lock.

        This should only be used for setting the state to DISCONNECTED
        after cancelling an attempt that has not yet established a
        socket (RESOLVING, or CONNECTING before the socket connected).
        """
        self._connection_state = state

    def _first_try_log_level(self) -> int:
        """WARNING on the first attempt of a reconnect cycle, DEBUG after."""
        return logging.WARNING if self._tries == 0 else logging.DEBUG

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
        elif isinstance(err, APIConnectionCancelledError):
            # APIConnectionCancelledError is harmless and should always be DEBUG
            level = logging.DEBUG
        else:
            level = self._first_try_log_level()
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
            await self._cli.start_resolve_host(
                on_stop=self._on_disconnect, log_errors=False
            )
        except Exception as err:  # noqa: BLE001  # pylint: disable=broad-except
            await self._handle_connection_failure(err)
            return False
        self._async_set_connection_state_while_locked(ReconnectLogicState.CONNECTING)
        start_connect_time = time.perf_counter()
        resolve_time = start_connect_time - start_resolve_time
        _LOGGER.log(
            logging.INFO if self._tries == 0 else logging.DEBUG,
            "Successfully resolved %s in %0.3fs",
            self._cli.log_name,
            resolve_time,
        )
        try:
            await self._cli.start_connection()
        except Exception as err:  # noqa: BLE001  # pylint: disable=broad-except
            await self._handle_connection_failure(err)
            return False
        finish_connect_time = time.perf_counter()
        connect_time = finish_connect_time - start_connect_time
        _LOGGER.info(
            "Successfully connected to %s in %0.3fs", self._cli.log_name, connect_time
        )
        self._zc_wake.stop()
        self._async_set_connection_state_while_locked(ReconnectLogicState.HANDSHAKING)
        try:
            await self._cli.finish_connection(login=True)
        except Exception as err:  # noqa: BLE001  # pylint: disable=broad-except
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
        # Remember deep-sleep from the device_info the connect callback just
        # fetched; the client clears its cache on disconnect, so capture it now
        # while connected. Persists on this long-lived object to cap the next
        # reconnect's backoff, and self-heals if the device's config changes.
        # None means device_info was not fetched, so leave any override intact.
        if (has_deep_sleep := self._cli.cached_device_has_deep_sleep) is not None:
            self.deep_sleep = has_deep_sleep
        return True

    async def _handle_connection_failure(self, err: Exception) -> None:
        """Handle a connection failure."""
        self._async_set_connection_state_while_locked(ReconnectLogicState.DISCONNECTED)
        # The attempt has truly ended — allow the next mDNS record to
        # kick a fresh connect attempt early.
        self._zc_wake.reopen()
        if self._on_connect_error_cb is not None:
            await self._on_connect_error_cb(err)
        self._async_log_connection_error(err)
        if (
            self._allow_plaintext_fallback
            and isinstance(err, EncryptionPlaintextAPIError)
            and self._cli.noise_psk is not None
        ):
            # Device firmware is running plaintext but the client has a
            # PSK configured. Downgrade so subsequent reconnect attempts
            # use plaintext; warn so the caller sees that it happened.
            _LOGGER.warning(
                "%s: Device is using plaintext protocol; disabling "
                "encryption for this session and retrying. The device's "
                "identity cannot be verified without encryption, so this "
                "session may be talking to a different device.",
                self._cli.log_name,
            )
            self._cli.clear_noise_psk()
            self._tries = 0
            return
        if isinstance(err, AUTH_EXCEPTIONS):
            # If we get an encryption or password error,
            # backoff for the maximum amount of time
            self._tries = MAXIMUM_BACKOFF_TRIES
        else:
            self._tries += 1

    def _schedule_connect(self, delay: float) -> None:
        """Schedule a connect attempt."""
        self._cancel_connect_timer()
        if not delay:
            self._call_connect_once()
            return
        _LOGGER.debug("Scheduling new connect attempt in %.2f seconds", delay)
        self._connect_timer = self.loop.call_at(
            self.loop.time() + delay, self._call_connect_once
        )

    def _call_connect_once(self) -> None:
        """Call the connect logic once.

        Must only be called from _schedule_connect or its scheduled timer.
        """
        if self._connect_task and not self._connect_task.done():
            if (
                self._connection_state != ReconnectLogicState.CONNECTING
                or self._cli.connected_address is not None
            ):
                # Connection state is far enough along that we should
                # not restart the connect task.
                #
                # Zeroconf triggering scenarios:
                # - RESOLVING state: Don't cancel, the resolve task will
                #   complete immediately since it's waiting for the same
                #   records zeroconf is delivering
                # - CONNECTING state with socket connected: Don't cancel,
                #   the device already accepted the TCP connection and we
                #   would waste the established connection
                # - CONNECTING state without socket: Cancel and restart to
                #   use potentially updated connection info from mDNS
                # - HANDSHAKING state or later: Don't cancel, too far along
                #   in the process
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
            self._zc_wake.arm()
            if await self._try_connect():
                return
            # Listen during the backoff wait without waiting out the arm timer.
            self._zc_wake.start_soon()
            tries = min(self._tries, 10)  # prevent OverflowError
            max_backoff = (
                DEEP_SLEEP_MAXIMUM_BACKOFF if self.deep_sleep else MAXIMUM_BACKOFF
            )
            wait_time = round(min(1.8**tries, max_backoff))
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

    def _on_addresses_changed(self) -> None:
        """Handle new candidate addresses appearing on the client.

        Try to connect with them right away instead of waiting out the
        backoff timer. _call_connect_once owns the restart policy for an
        in-flight attempt; only the RESOLVING case is handled here.
        """
        if self._is_stopped or self._connection_state not in NOT_YET_CONNECTED_STATES:
            # HANDSHAKING / READY: too far along to benefit; a later
            # attempt re-reads the address list anyway.
            return
        if self._connection_state is ReconnectLogicState.RESOLVING:
            # _call_connect_once won't restart a RESOLVING attempt (correct
            # for the mDNS kick, whose records are what the resolver is
            # waiting for); here the resolver may be pinned on a dead
            # hostname for its full timeout while the new addresses are
            # typically IP literals that resolve instantly, so cancel it.
            _LOGGER.debug(
                "%s: Cancelling resolve to try newly added addresses",
                self._cli.log_name,
            )
            self._cancel_connect_task("New addresses available")
            self._async_set_connection_state_without_lock(
                ReconnectLogicState.DISCONNECTED
            )
        # Re-arm the one-kick-per-attempt mDNS gate for the attempt this
        # schedules; harmless if _call_connect_once declines.
        self._zc_wake.reopen()
        self._schedule_connect(0.0)

    async def start(self) -> None:
        """Start the connecting logic background task."""
        async with self._connected_lock:
            self._is_stopped = False
            if self._connection_state != ReconnectLogicState.DISCONNECTED:
                return
            self._tries = 0
            # Clear any stale gate from a prior run that was stopped mid
            # attempt after an mDNS triggered restart.
            self._zc_wake.reopen()
            if self._unsub_addresses_changed is None:
                self._unsub_addresses_changed = (
                    self._cli.register_addresses_changed_callback(
                        self._on_addresses_changed
                    )
                )
            self._schedule_connect(0.0)

    async def stop(self) -> None:
        """Stop the connecting logic background task. Does not disconnect the client."""
        if self._unsub_addresses_changed is not None:
            self._unsub_addresses_changed()
            self._unsub_addresses_changed = None
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
            self._zc_wake.stop()
            self._async_set_connection_state_while_locked(
                ReconnectLogicState.DISCONNECTED
            )

        await self._zeroconf_manager.async_close()

    def _zc_can_kick(self) -> bool:
        """Return True while an mDNS record could still usefully kick a connect."""
        return (
            not self._is_stopped and self._connection_state in NOT_YET_CONNECTED_STATES
        )

    def _connect_from_zeroconf(self) -> None:
        """Connect from zeroconf."""
        self._schedule_connect(0.0)
