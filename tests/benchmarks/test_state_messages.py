"""Benchmarks for entity state message decoding.

These cover the hottest non-BLE path: every sensor reading, switch toggle,
light brightness change, climate update, etc., flows through
``APIConnection.process_packet`` -> protobuf parse -> handler dispatch ->
``on_state_msg`` -> ``EntityState.from_pb`` -> user callback.
"""

from functools import partial

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aioesphomeapi import APIConnection
from aioesphomeapi.api_pb2 import (
    BinarySensorStateResponse,
    ClimateStateResponse,
    LightStateResponse,
    SensorStateResponse,
    SwitchStateResponse,
)
from aioesphomeapi.client import APIClient
from aioesphomeapi.client_base import on_state_msg


def _make_connection() -> APIConnection:
    client = APIClient("fake.address", 6052, None)
    return APIConnection(client._params, lambda expected_disconnect: None, False, None)


def _noop_on_state(state: object) -> None:
    """No-op state callback."""


async def test_sensor_state_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark sensor state response decode (highest volume message)."""
    msg = SensorStateResponse(key=12345678, state=23.456, missing_state=False)
    data = msg.SerializeToString()

    connection = _make_connection()
    connection.add_message_callback(
        partial(on_state_msg, _noop_on_state, {}),
        (SensorStateResponse,),
    )

    process = partial(connection.process_packet, 25, data)
    benchmark(process)


async def test_binary_sensor_state_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark binary sensor state response decode."""
    msg = BinarySensorStateResponse(key=12345678, state=True, missing_state=False)
    data = msg.SerializeToString()

    connection = _make_connection()
    connection.add_message_callback(
        partial(on_state_msg, _noop_on_state, {}),
        (BinarySensorStateResponse,),
    )

    process = partial(connection.process_packet, 21, data)
    benchmark(process)


async def test_switch_state_response(benchmark: BenchmarkFixture) -> None:
    """Benchmark switch state response decode."""
    msg = SwitchStateResponse(key=12345678, state=True)
    data = msg.SerializeToString()

    connection = _make_connection()
    connection.add_message_callback(
        partial(on_state_msg, _noop_on_state, {}),
        (SwitchStateResponse,),
    )

    process = partial(connection.process_packet, 26, data)
    benchmark(process)


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
    data = msg.SerializeToString()

    connection = _make_connection()
    connection.add_message_callback(
        partial(on_state_msg, _noop_on_state, {}),
        (LightStateResponse,),
    )

    process = partial(connection.process_packet, 24, data)
    benchmark(process)


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
    data = msg.SerializeToString()

    connection = _make_connection()
    connection.add_message_callback(
        partial(on_state_msg, _noop_on_state, {}),
        (ClimateStateResponse,),
    )

    process = partial(connection.process_packet, 47, data)
    benchmark(process)


async def test_mixed_state_responses(benchmark: BenchmarkFixture) -> None:
    """Benchmark a realistic mix of state types in one batch.

    Real installs interleave sensor/binary/switch/light updates; this measures
    dispatch lookup cost across multiple registered message types.
    """
    sensor_data = SensorStateResponse(
        key=1, state=23.456, missing_state=False
    ).SerializeToString()
    binary_data = BinarySensorStateResponse(
        key=2, state=True, missing_state=False
    ).SerializeToString()
    switch_data = SwitchStateResponse(key=3, state=True).SerializeToString()
    light_data = LightStateResponse(
        key=4, state=True, brightness=0.75
    ).SerializeToString()

    connection = _make_connection()
    handler = partial(on_state_msg, _noop_on_state, {})
    connection.add_message_callback(
        handler,
        (
            SensorStateResponse,
            BinarySensorStateResponse,
            SwitchStateResponse,
            LightStateResponse,
        ),
    )

    process_packet = connection.process_packet
    batch = (
        (25, sensor_data),
        (21, binary_data),
        (26, switch_data),
        (24, light_data),
    ) * 25

    @benchmark
    def process_batch() -> None:
        for msg_type, data in batch:
            process_packet(msg_type, data)
