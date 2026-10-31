"""End-to-end: a logs session reconnects as soon as its device announces itself."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import TYPE_CHECKING, Any
import uuid

import pytest
import zeroconf.asyncio as zc_asyncio

from aioesphomeapi import APIClient
from aioesphomeapi.client_base import KEEP_ALIVE_FREQUENCY
from aioesphomeapi.log_runner import async_run

from .fake_device import BOOT_LOG_LINE, ESP32_IDF, LOOPBACK, FakeDevice

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

    from aioesphomeapi.api_pb2 import SubscribeLogsResponse  # type: ignore[attr-defined]

_BACKOFF = re.compile(r"Scheduling new connect attempt in ([0-9.]+) seconds")
# Retries this far apart leave the announcement as the only quick way back.
MIN_BACKOFF = 3.0
# Short so a stale session left by a reboot is found quickly.
STALE_KEEPALIVE = 2.0


class LogsSession:
    """A logs session started like esphome logs, without a zeroconf instance."""

    def __init__(self, device: FakeDevice, keepalive: float) -> None:
        self.device = device
        self.log_times: list[float] = []
        self._cli = APIClient(LOOPBACK, device.port, None, keepalive=keepalive)
        self._stop: Callable[[], Awaitable[None]] | None = None

    async def start(self) -> None:
        """Run logs and wait for the first log line."""
        self._stop = await async_run(
            self._cli, self._on_log, name=self.device.name, subscribe_states=True
        )
        assert await self.wait_log(0, 10) is not None

    async def stop(self) -> None:
        """Stop the logs session."""
        if self._stop is not None:
            await self._stop()

    async def wait_log(self, after: float, timeout: float) -> float | None:
        """Return when the first log line after after arrived, or None after timeout."""
        for _ in range(int(timeout / 0.01)):
            for when in self.log_times:
                if when > after:
                    return when
            await asyncio.sleep(0.01)
        return None

    def _on_log(self, msg: SubscribeLogsResponse) -> None:
        if msg.message == BOOT_LOG_LINE:
            self.log_times.append(time.time())


@pytest.fixture(autouse=True)
def _private_zeroconf_on_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the zeroconf the client creates for itself on loopback."""
    original = zc_asyncio.AsyncZeroconf

    class LoopbackAsyncZeroconf(original):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(interfaces=[LOOPBACK])

    monkeypatch.setattr(zc_asyncio, "AsyncZeroconf", LoopbackAsyncZeroconf)


@pytest.fixture
async def logs_device(
    mdns: tuple[zc_asyncio.AsyncZeroconf, zc_asyncio.AsyncZeroconf],
    caplog: pytest.LogCaptureFixture,
) -> AsyncGenerator[Callable[[float], Awaitable[LogsSession]]]:
    """Return a factory for a FakeDevice with a running logs session on it."""
    caplog.set_level(logging.DEBUG, logger="aioesphomeapi.reconnect_logic")
    responder, _ = mdns
    sessions: list[LogsSession] = []

    async def _make(keepalive: float = KEEP_ALIVE_FREQUENCY) -> LogsSession:
        device = FakeDevice(f"e2e-logs-{uuid.uuid4().hex[:8]}", responder)
        await device.start()
        session = LogsSession(device, keepalive)
        sessions.append(session)
        await session.start()
        return session

    yield _make
    for session in sessions:
        await session.stop()
        await session.device.stop()


async def _wait_for_backoff(caplog: pytest.LogCaptureFixture, timeout: float) -> None:
    """Wait until a reconnect is scheduled at least MIN_BACKOFF seconds out."""
    for _ in range(int(timeout / 0.05)):
        for record in caplog.records:
            if (match := _BACKOFF.search(record.getMessage())) and float(
                match.group(1)
            ) >= MIN_BACKOFF:
                return
        await asyncio.sleep(0.05)
    pytest.fail("the reconnect never backed off")


async def test_logs_resume_on_announcement_after_device_went_offline(
    logs_device: Callable[[float], Awaitable[LogsSession]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A device that went offline is reconnected on its announcement, not its backoff."""
    session = await logs_device(KEEP_ALIVE_FREQUENCY)
    await session.device.stop()
    await _wait_for_backoff(caplog, 15)
    await session.device.start()
    announced = time.time()
    announce = asyncio.create_task(session.device.announce(ESP32_IDF))
    resumed = await session.wait_log(announced, 3)
    await announce
    assert resumed is not None, "logs did not resume"
    assert resumed - announced < 1.0
    assert "Triggering connect because of received mDNS record" in caplog.text
    assert "repeated mDNS announcement" not in caplog.text


async def test_logs_resume_on_announcement_after_device_rebooted(
    logs_device: Callable[[float], Awaitable[LogsSession]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A reboot leaves a stale session; once it is found, the boot announcement reconnects."""
    session = await logs_device(STALE_KEEPALIVE)
    session.device.reboot()
    await session.device.stop(drop_connections=False)
    await _wait_for_backoff(caplog, STALE_KEEPALIVE + 15)
    await session.device.start()
    announced = time.time()
    announce = asyncio.create_task(session.device.announce(ESP32_IDF))
    resumed = await session.wait_log(announced, 3)
    await announce
    assert resumed is not None, "logs did not resume"
    assert resumed - announced < 1.0
    assert "Triggering connect because of received mDNS record" in caplog.text
    assert "repeated mDNS announcement" not in caplog.text
