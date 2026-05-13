"""Benchmarks for ListEntities response decoding.

When Home Assistant connects (or reconnects) to an ESPHome device, every
entity definition is sent as a ``ListEntities*Response``. Devices with many
entities (Bluetooth proxies, status panels, multi-sensor boards) make HA
startup feel slow if this path regresses.

These cover both ``process_packet`` (parse + dispatch) and the subsequent
``EntityInfo.from_pb`` conversion that the client does after collecting all
list-entities messages.
"""

from functools import partial

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aioesphomeapi.api_pb2 import (
    ListEntitiesBinarySensorResponse,
    ListEntitiesClimateResponse,
    ListEntitiesLightResponse,
    ListEntitiesSensorResponse,
    ListEntitiesSwitchResponse,
)
from aioesphomeapi.model import (
    BinarySensorInfo,
    ClimateInfo,
    LightInfo,
    SensorInfo,
    SwitchInfo,
)

from .helpers import bench_process_packet, make_connection, noop


def _sensor_info() -> ListEntitiesSensorResponse:
    return ListEntitiesSensorResponse(
        object_id="living_room_temperature",
        key=12345678,
        name="Living Room Temperature",
        icon="mdi:thermometer",
        unit_of_measurement="°C",
        accuracy_decimals=2,
        force_update=False,
        device_class="temperature",
        state_class=1,
        disabled_by_default=False,
        entity_category=0,
    )


def _binary_sensor_info() -> ListEntitiesBinarySensorResponse:
    return ListEntitiesBinarySensorResponse(
        object_id="motion_sensor",
        key=12345679,
        name="Motion Sensor",
        device_class="motion",
        is_status_binary_sensor=False,
        disabled_by_default=False,
        icon="mdi:motion-sensor",
        entity_category=0,
    )


def _switch_info() -> ListEntitiesSwitchResponse:
    return ListEntitiesSwitchResponse(
        object_id="relay_1",
        key=12345680,
        name="Relay 1",
        icon="mdi:power-socket",
        assumed_state=False,
        disabled_by_default=False,
        entity_category=0,
        device_class="outlet",
    )


def _light_info() -> ListEntitiesLightResponse:
    return ListEntitiesLightResponse(
        object_id="rgbww_light",
        key=12345681,
        name="RGBWW Light",
        supported_color_modes=[1, 3, 11, 35, 47],
        min_mireds=153.0,
        max_mireds=500.0,
        effects=["None", "Rainbow", "Color Wipe", "Random", "Strobe"],
        legacy_supports_brightness=True,
        legacy_supports_rgb=True,
        legacy_supports_white_value=True,
        legacy_supports_color_temperature=True,
        disabled_by_default=False,
        icon="mdi:lightbulb",
        entity_category=0,
    )


def _climate_info() -> ListEntitiesClimateResponse:
    return ListEntitiesClimateResponse(
        object_id="hvac",
        key=12345682,
        name="HVAC",
        supports_current_temperature=True,
        supports_two_point_target_temperature=True,
        supported_modes=[0, 1, 2, 3, 4, 5],
        visual_min_temperature=10.0,
        visual_max_temperature=32.0,
        visual_target_temperature_step=0.5,
        visual_current_temperature_step=0.1,
        supports_action=True,
        supported_fan_modes=[0, 1, 2, 3, 4, 5, 6],
        supported_swing_modes=[0, 1, 2, 3],
        supported_custom_fan_modes=["quiet", "turbo"],
        supported_presets=[0, 1, 2, 3, 4, 5, 6, 7],
        supported_custom_presets=["sleep", "vacation"],
        disabled_by_default=False,
        icon="mdi:hvac",
        entity_category=0,
        supports_current_humidity=True,
        supports_target_humidity=True,
        visual_min_humidity=30.0,
        visual_max_humidity=70.0,
        feature_flags=0,
        temperature_unit=0,
    )


def test_list_entities_sensor_from_pb(benchmark: BenchmarkFixture) -> None:
    """Benchmark SensorInfo.from_pb (model construction cost only)."""
    benchmark(partial(SensorInfo.from_pb, _sensor_info()))


def test_list_entities_binary_sensor_from_pb(benchmark: BenchmarkFixture) -> None:
    """Benchmark BinarySensorInfo.from_pb."""
    benchmark(partial(BinarySensorInfo.from_pb, _binary_sensor_info()))


def test_list_entities_switch_from_pb(benchmark: BenchmarkFixture) -> None:
    """Benchmark SwitchInfo.from_pb."""
    benchmark(partial(SwitchInfo.from_pb, _switch_info()))


def test_list_entities_light_from_pb(benchmark: BenchmarkFixture) -> None:
    """Benchmark LightInfo.from_pb (lists + enum convert)."""
    benchmark(partial(LightInfo.from_pb, _light_info()))


def test_list_entities_climate_from_pb(benchmark: BenchmarkFixture) -> None:
    """Benchmark ClimateInfo.from_pb (widest entity info, many list converts)."""
    benchmark(partial(ClimateInfo.from_pb, _climate_info()))


async def test_list_entities_sensor_process_packet(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark process_packet for a sensor list entities response."""
    benchmark(bench_process_packet(_sensor_info(), 16))


async def test_list_entities_climate_process_packet(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark process_packet for a climate list entities response."""
    benchmark(bench_process_packet(_climate_info(), 46))


async def test_list_entities_typical_device_batch(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark a realistic device entity dump.

    Models a moderately complex ESPHome device (e.g. multi sensor board with a
    relay, a climate component, and an RGBWW light) that emits a mix of list
    entities responses at connect time.
    """
    sensor_msg = _sensor_info().SerializeToString()
    binary_msg = _binary_sensor_info().SerializeToString()
    switch_msg = _switch_info().SerializeToString()
    light_msg = _light_info().SerializeToString()
    climate_msg = _climate_info().SerializeToString()

    connection = make_connection()
    connection.add_message_callback(
        noop,
        (
            ListEntitiesSensorResponse,
            ListEntitiesBinarySensorResponse,
            ListEntitiesSwitchResponse,
            ListEntitiesLightResponse,
            ListEntitiesClimateResponse,
        ),
    )
    process_packet = connection.process_packet
    batch = (
        (16, sensor_msg),
        (16, sensor_msg),
        (16, sensor_msg),
        (12, binary_msg),
        (12, binary_msg),
        (17, switch_msg),
        (17, switch_msg),
        (15, light_msg),
        (46, climate_msg),
    )

    @benchmark
    def process_batch() -> None:
        for msg_type, data in batch:
            process_packet(msg_type, data)
