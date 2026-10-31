"""End-to-end: mDNS announcements probe, kick and leave sessions alone as intended."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import logging
import time
from typing import TYPE_CHECKING

import pytest

import aioesphomeapi._zc_listener as zc_listener
from aioesphomeapi.client_base import KEEP_ALIVE_FREQUENCY
from aioesphomeapi.reconnect_logic import ANNOUNCE_BURST_WINDOW_MS

from .conftest import DeviceClient
from .fake_device import DELIVERY_WAIT

if TYPE_CHECKING:
    from zeroconf.asyncio import AsyncZeroconf

MakeDevice = Callable[[], Awaitable[DeviceClient]]
ProbeLog = Callable[[str], list[float]]

# Rounds of (ms before the round, packet kinds) after a reboot, per responder.
ESP32_IDF = [(300.0, ("all",)), (1005.0, ("all",)), (1005.0, ("all",))]
# The 2nd copy lands inside zeroconf's 1000 ms duplicate packet suppression.
ESP32_IDF_SECOND_SUPPRESSED = [(300.0, ("all",)), (990.0, ("all",)), (1010.0, ("all",))]
LEAMDNS = [(300.0, ("host", "service"))] + [(1000.0, ("host", "service"))] * 3
LWIP = [(300.0, ("all",)), (1005.0, ("all",))]
LWIP_SECOND_SUPPRESSED = [(300.0, ("all",)), (990.0, ("all",))]


def _dispatchers(aiozc: AsyncZeroconf) -> int:
    return sum(
        isinstance(listener, zc_listener.ZeroconfRecordDispatcher)
        for listener in aiozc.zeroconf.record_manager.listeners
    )


async def test_connected_devices_share_one_listener(
    mdns: tuple[AsyncZeroconf, AsyncZeroconf], make_device: MakeDevice
) -> None:
    """Two connected devices on one zeroconf share a listener removed with the last."""
    _, client_zc = mdns
    first = await make_device()
    second = await make_device()
    assert _dispatchers(client_zc) == 1
    await first.logic.stop()
    assert _dispatchers(client_zc) == 1
    await second.logic.stop()
    assert _dispatchers(client_zc) == 0


async def test_solicited_answers_do_not_probe(
    make_device: MakeDevice, probe_log: ProbeLog
) -> None:
    """Single answers outside the burst window and a split answer never ping."""
    client = await make_device()
    for _ in range(3):
        client.device.send_packet()
        await asyncio.sleep(ANNOUNCE_BURST_WINDOW_MS / 1000 + 0.5)
    client.device.send_packet("host")
    await asyncio.sleep(0.2)
    client.device.send_packet("service")
    await asyncio.sleep(DELIVERY_WAIT)
    assert probe_log(client.device.name) == []
    assert client.connected.is_set()
    assert client.disconnect_times == []


@pytest.mark.parametrize(
    "rounds",
    [ESP32_IDF, ESP32_IDF_SECOND_SUPPRESSED, LEAMDNS, LWIP],
    ids=["esp32-idf", "esp32-idf-2nd-suppressed", "leamdns-split", "lwip"],
)
async def test_reboot_detected_by_announcement_burst(
    make_device: MakeDevice,
    probe_log: ProbeLog,
    rounds: list[tuple[float, tuple[str, ...]]],
) -> None:
    """A reboot burst pings the stale session, which drops; the new one is left alone."""
    client = await make_device()
    rebooted = time.monotonic()
    client.device.reboot()
    announce = asyncio.create_task(client.device.announce(rounds))
    dropped = await client.wait_disconnected(rebooted, 5)
    assert dropped is not None, "the stale session was not dropped"
    probes = probe_log(client.device.name)
    assert probes, "no probe ping was sent"
    assert probes[0] <= dropped
    assert await client.wait_connected(5)
    await announce
    reconnected = client.connect_times[-1]
    assert [when for when in probe_log(client.device.name) if when > reconnected] == []


async def test_lwip_second_announce_suppressed_falls_back_to_keepalive(
    make_device: MakeDevice, probe_log: ProbeLog
) -> None:
    """With lwIP's 2nd announcement suppressed, only the regular keepalive finds the reboot."""
    client = await make_device()
    rebooted = time.monotonic()
    client.device.reboot()
    await client.device.announce(LWIP_SECOND_SUPPRESSED)
    dropped = await client.wait_disconnected(rebooted, KEEP_ALIVE_FREQUENCY + 5)
    assert dropped is not None
    assert probe_log(client.device.name) == []


async def test_disconnected_device_kicked_by_announcement(
    make_device: MakeDevice,
    probe_log: ProbeLog,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The first announcement kicks a backed-off reconnect; the rest of its burst never pings."""
    caplog.set_level(logging.DEBUG, logger="aioesphomeapi.reconnect_logic")
    client = await make_device()
    await client.device.stop()
    assert await client.wait_disconnected(0, 5) is not None
    # Wait out the immediate retries so the next attempt is a backoff away.
    await asyncio.sleep(4)
    assert not client.connected.is_set()
    await client.device.start()
    announced = time.monotonic()
    announce = asyncio.create_task(client.device.announce(ESP32_IDF))
    assert await client.wait_connected(2)
    reconnected = client.connect_times[-1]
    assert reconnected - announced < 1.0
    assert "Triggering connect because of received mDNS record" in caplog.text
    await announce
    assert [when for when in probe_log(client.device.name) if when > reconnected] == []
