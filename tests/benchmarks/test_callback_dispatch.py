"""Benchmark cost of exception guards around user callbacks.

Motivation (issue #1755): ``APIConnection.process_packet`` invokes user
callbacks directly without exception isolation. A buggy callback can
unwind through the frame helper into asyncio's ``data_received`` and
tear down the whole ESPHome session. Most ``on_*_response`` sites in
``client_base.py`` run user code unguarded; only
``on_bluetooth_gatt_notify_data_response`` wraps the call in try/except
today.

Two hardening options are on the table:

1. Wrap the dispatch in ``process_packet`` itself — uniform isolation,
   pays per dispatch on the Cython hot path.
2. Wrap the user-supplied callback at each ``on_*_response`` site —
   pays per registered handler kind in Python.

These benchmarks measure the per-dispatch cost of the per-site approach
(2) so the maintainer can decide whether the protection is worth the
throughput cost on a large install. Cython try/except inside
``process_packet`` (option 1) is bounded above by these numbers since
Cython's exception handling is typically cheaper than Python's.
"""

from __future__ import annotations

from functools import partial
import logging
from typing import TYPE_CHECKING

from aioesphomeapi.api_pb2 import (
    BluetoothLERawAdvertisement,
    BluetoothLERawAdvertisementsResponse,
    ClimateStateResponse,
    SensorStateResponse,
)
from aioesphomeapi.client_base import on_state_msg

from .helpers import make_connection, noop

if TYPE_CHECKING:
    from collections.abc import Callable

    from google.protobuf import message
    from pytest_codspeed import BenchmarkFixture

_LOGGER = logging.getLogger(__name__)


def _guarded(handler: Callable[[object], None]) -> Callable[[object], None]:
    """Wrap ``handler`` in the same try/except pattern used by the GATT-notify site."""

    def wrapper(msg: object) -> None:
        try:
            handler(msg)
        except Exception:
            _LOGGER.exception("benchmark: handler raised")

    return wrapper


def _raising(_msg: object) -> None:
    msg = "simulated handler bug"
    raise RuntimeError(msg)


def _bench(
    msg: message.Message, msg_type: int, handler: Callable[[object], None]
) -> Callable[[], None]:
    connection = make_connection()
    connection.add_message_callback(handler, (type(msg),))
    data = msg.SerializeToString()
    return partial(connection.process_packet, msg_type, data)


# -- Single-handler dispatch (the common case in process_packet) -----------


async def test_sensor_unguarded(benchmark: BenchmarkFixture) -> None:
    """Baseline: sensor update, no per-site try/except (current behavior)."""
    msg = SensorStateResponse(key=12345678, state=23.456, missing_state=False)
    benchmark(_bench(msg, 25, partial(on_state_msg, noop, {})))


async def test_sensor_guarded(benchmark: BenchmarkFixture) -> None:
    """Sensor update with per-site try/except around the user callback."""
    msg = SensorStateResponse(key=12345678, state=23.456, missing_state=False)
    benchmark(_bench(msg, 25, _guarded(partial(on_state_msg, noop, {}))))


async def test_climate_unguarded(benchmark: BenchmarkFixture) -> None:
    """Baseline: wide-state climate update, no guard."""
    msg = ClimateStateResponse(
        key=12345678,
        mode=3,
        action=2,
        current_temperature=21.5,
        target_temperature=22.0,
        target_temperature_low=20.0,
        target_temperature_high=24.0,
        fan_mode=3,
        swing_mode=1,
        custom_fan_mode="quiet",
        preset=1,
        custom_preset="",
        current_humidity=45.0,
        target_humidity=50.0,
    )
    benchmark(_bench(msg, 47, partial(on_state_msg, noop, {})))


async def test_climate_guarded(benchmark: BenchmarkFixture) -> None:
    """Climate update with per-site try/except around the user callback."""
    msg = ClimateStateResponse(
        key=12345678,
        mode=3,
        action=2,
        current_temperature=21.5,
        target_temperature=22.0,
        target_temperature_low=20.0,
        target_temperature_high=24.0,
        fan_mode=3,
        swing_mode=1,
        custom_fan_mode="quiet",
        preset=1,
        custom_preset="",
        current_humidity=45.0,
        target_humidity=50.0,
    )
    benchmark(_bench(msg, 47, _guarded(partial(on_state_msg, noop, {}))))


async def test_raw_ble_advs_unguarded(benchmark: BenchmarkFixture) -> None:
    """Baseline: raw BLE advertisement batch, no guard."""
    msg = BluetoothLERawAdvertisementsResponse()
    fake = BluetoothLERawAdvertisement(
        address=1, rssi=-86, address_type=2, data=b"\x01\x02\x03\x04"
    )
    for _ in range(5):
        msg.advertisements.append(fake)
    benchmark(_bench(msg, 93, noop))


async def test_raw_ble_advs_guarded(benchmark: BenchmarkFixture) -> None:
    """Raw BLE advertisement batch with per-site try/except."""
    msg = BluetoothLERawAdvertisementsResponse()
    fake = BluetoothLERawAdvertisement(
        address=1, rssi=-86, address_type=2, data=b"\x01\x02\x03\x04"
    )
    for _ in range(5):
        msg.advertisements.append(fake)
    benchmark(_bench(msg, 93, _guarded(noop)))


# -- Multi-handler dispatch (len(handlers) > 1 forces set-copy branch) ----


async def test_sensor_multi_handler_unguarded(benchmark: BenchmarkFixture) -> None:
    """Multi-handler dispatch with two registered callbacks, no guard."""
    msg = SensorStateResponse(key=12345678, state=23.456, missing_state=False)
    connection = make_connection()
    connection.add_message_callback(
        partial(on_state_msg, noop, {}), (SensorStateResponse,)
    )
    connection.add_message_callback(
        partial(on_state_msg, noop, {}), (SensorStateResponse,)
    )
    data = msg.SerializeToString()
    benchmark(partial(connection.process_packet, 25, data))


async def test_sensor_multi_handler_guarded(benchmark: BenchmarkFixture) -> None:
    """Multi-handler dispatch with per-site try/except on each callback."""
    msg = SensorStateResponse(key=12345678, state=23.456, missing_state=False)
    connection = make_connection()
    connection.add_message_callback(
        _guarded(partial(on_state_msg, noop, {})), (SensorStateResponse,)
    )
    connection.add_message_callback(
        _guarded(partial(on_state_msg, noop, {})), (SensorStateResponse,)
    )
    data = msg.SerializeToString()
    benchmark(partial(connection.process_packet, 25, data))


# -- Worst case: handler raises on every call -----------------------------


async def test_sensor_raising_handler_guarded(benchmark: BenchmarkFixture) -> None:
    """Cost when the guarded handler raises every call (worst-case, rare)."""
    msg = SensorStateResponse(key=12345678, state=23.456, missing_state=False)
    benchmark(_bench(msg, 25, _guarded(_raising)))
