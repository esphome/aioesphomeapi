"""Fixtures for the end-to-end mDNS tests; all multicast stays on loopback."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from typing import TYPE_CHECKING
import uuid

import pytest
from zeroconf import RecordUpdate, RecordUpdateListener, Zeroconf
from zeroconf.asyncio import AsyncZeroconf

from aioesphomeapi import APIClient, ReconnectLogic
from aioesphomeapi.client_base import KEEP_ALIVE_FREQUENCY

from .fake_device import LOOPBACK, FakeDevice

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

# CI sets this so a runner without loopback multicast fails instead of skipping.
REQUIRE_MDNS = os.environ.get("AIOESPHOMEAPI_E2E_REQUIRE_MDNS") == "1"


class _Seen(RecordUpdateListener):
    """Set an event when a record named name arrives."""

    def __init__(self, name: str) -> None:
        self._name = name
        self.event = asyncio.Event()

    def async_update_records(
        self, zc: Zeroconf, now: float, records: list[RecordUpdate]
    ) -> None:
        if any(update.new.key == self._name for update in records):
            self.event.set()


class DeviceClient:
    """A ReconnectLogic session to a FakeDevice that records connects and disconnects."""

    def __init__(
        self, device: FakeDevice, aiozc: AsyncZeroconf, keepalive: float
    ) -> None:
        self.device = device
        self.connected = asyncio.Event()
        self.connect_times: list[float] = []
        self.disconnect_times: list[float] = []
        self.cli = APIClient(LOOPBACK, device.port, None, keepalive=keepalive)
        self.logic = ReconnectLogic(
            client=self.cli,
            on_connect=self._on_connect,
            on_disconnect=self._on_disconnect,
            zeroconf_instance=aiozc,
            name=device.name,
        )

    async def start(self) -> None:
        """Connect and wait until the session and its mDNS listener are up."""
        await self.logic.start()
        await asyncio.wait_for(self.connected.wait(), 10)
        if (task := self.logic._zc_wake._start_task) is not None:
            await task

    async def wait_connected(self, timeout: float) -> bool:
        """Return True once a session is up, False after timeout seconds."""
        try:
            await asyncio.wait_for(self.connected.wait(), timeout)
        except TimeoutError:
            return False
        return True

    async def wait_disconnected(self, after: float, timeout: float) -> float | None:
        """Return the first disconnect time after after, or None after timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            for when in self.disconnect_times:
                if when > after:
                    return when
            await asyncio.sleep(0.01)
        return None

    async def _on_connect(self) -> None:
        self.connect_times.append(time.time())
        self.connected.set()

    async def _on_disconnect(self, expected_disconnect: bool) -> None:
        self.disconnect_times.append(time.time())
        self.connected.clear()


@pytest.fixture
def probe_log(caplog: pytest.LogCaptureFixture) -> Callable[[str], list[float]]:
    """Return a lookup of the times probe pings were logged for a device."""
    caplog.set_level(logging.DEBUG, logger="aioesphomeapi.reconnect_logic")

    def probes(name: str) -> list[float]:
        return [
            record.created
            for record in caplog.records
            if "Sending keepalive ping because of repeated mDNS announcement"
            in record.getMessage()
            and name in record.getMessage()
        ]

    return probes


@pytest.fixture
async def mdns() -> AsyncGenerator[tuple[AsyncZeroconf, AsyncZeroconf]]:
    """Yield a device-side responder and the client's shared zeroconf, on loopback."""
    responder = AsyncZeroconf(interfaces=[LOOPBACK])
    client_zc = AsyncZeroconf(interfaces=[LOOPBACK])
    try:
        await responder.zeroconf.async_wait_for_start()
        await client_zc.zeroconf.async_wait_for_start()
        probe = FakeDevice(f"e2e-probe-{uuid.uuid4().hex[:8]}", responder)
        seen = _Seen(f"{probe.name}.local.")
        client_zc.zeroconf.async_add_listener(seen, None)
        for _ in range(10):
            probe.send_packet("host")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(seen.event.wait(), 0.2)
                break
        client_zc.zeroconf.async_remove_listener(seen)
        if not seen.event.is_set():
            message = "multicast on loopback is not delivered on this host"
            if REQUIRE_MDNS:
                pytest.fail(message)
            pytest.skip(message)
        yield responder, client_zc
    finally:
        await client_zc.async_close()
        await responder.async_close()


@pytest.fixture
async def make_device(
    mdns: tuple[AsyncZeroconf, AsyncZeroconf],
) -> AsyncGenerator[Callable[..., Awaitable[DeviceClient]]]:
    """Return a factory that starts a uniquely named FakeDevice plus a connected client."""
    responder, client_zc = mdns
    clients: list[DeviceClient] = []

    async def _make(keepalive: float = KEEP_ALIVE_FREQUENCY) -> DeviceClient:
        device = FakeDevice(f"e2e-{uuid.uuid4().hex[:8]}", responder)
        await device.start()
        client = DeviceClient(device, client_zc, keepalive)
        clients.append(client)
        await client.start()
        return client

    yield _make
    for client in clients:
        await client.logic.stop()
        await client.cli.disconnect(force=True)
        await client.device.stop()
