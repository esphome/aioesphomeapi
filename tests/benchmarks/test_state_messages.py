"""Benchmarks for entity state message decoding.

These cover the hottest non-BLE path: every sensor reading, switch toggle,
light brightness change, climate update, etc., flows through
``APIConnection.process_packet`` -> protobuf parse -> handler dispatch ->
``on_state_msg`` -> ``EntityState.from_pb`` -> user callback.
"""

from functools import partial

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aioesphomeapi.api_pb2 import (
    BinarySensorStateResponse,
    ClimateStateResponse,
    LightStateResponse,
    SensorStateResponse,
    SwitchStateResponse,
)
from aioesphomeapi.client_base import on_state_msg

from .helpers import bench_state_process_packet, make_connection, noop


async def test_sensor_state_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark sensor state response decode (highest volume message)."""
    msg = SensorStateResponse(key=12345678, state=23.456, missing_state=False)
    benchmark(bench_state_process_packet(msg, 25))


async def test_binary_sensor_state_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark binary sensor state response decode."""
    msg = BinarySensorStateResponse(key=12345678, state=True, missing_state=False)
    benchmark(bench_state_process_packet(msg, 21))


async def test_switch_state_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark switch state response decode."""
    msg = SwitchStateResponse(key=12345678, state=True)
    benchmark(bench_state_process_packet(msg, 26))


async def test_light_state_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark light state response decode (many float fields)."""
    msg = LightStateResponse(
        key=12345678,
        state=True,
        brightness=0.75,
        color_mode=35,
        color_brightness=1.0,
        red=0.5,
        green=0.25,
        blue=0.125,
        white=0.0,
        color_temperature=350.0,
        cold_white=0.0,
        warm_white=0.0,
        effect="None",
    )
    benchmark(bench_state_process_packet(msg, 24))


async def test_climate_state_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark climate state response decode (widest entity state)."""
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
    benchmark(bench_state_process_packet(msg, 47))


async def test_mixed_state_responses(benchmark: BenchmarkFixture) -> None:
    """Benchmark a realistic mix of state types in one batch.

    Real installs interleave sensor/binary/switch/light updates; this measures
    dispatch lookup cost across multiple registered message types.
    """
    batch = (
        tuple(
            (msg_type, msg.SerializeToString())
            for msg, msg_type in (
                (SensorStateResponse(key=1, state=23.456, missing_state=False), 25),
                (BinarySensorStateResponse(key=2, state=True, missing_state=False), 21),
                (SwitchStateResponse(key=3, state=True), 26),
                (LightStateResponse(key=4, state=True, brightness=0.75), 24),
            )
        )
        * 25
    )

    connection = make_connection()
    connection.add_message_callback(
        partial(on_state_msg, noop, {}),
        (
            SensorStateResponse,
            BinarySensorStateResponse,
            SwitchStateResponse,
            LightStateResponse,
        ),
    )
    process_packet = connection.process_packet

    @benchmark
    def process_batch() -> None:
        for msg_type, data in batch:
            process_packet(msg_type, data)
