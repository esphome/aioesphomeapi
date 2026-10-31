"""Benchmarks for the shared mDNS wake listener."""

from ipaddress import ip_address
from unittest.mock import MagicMock

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]
from zeroconf import DNSAddress, DNSNsec, DNSPointer, DNSService, DNSText, RecordUpdate
from zeroconf.const import (
    _CLASS_IN,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_NSEC,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
)

from aioesphomeapi._zc_listener import ZeroconfRecordDispatcher
from aioesphomeapi.client import APIClient
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState

LAN_SERVICES = (
    "_hap._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_ipp._tcp.local.",
)


async def _noop_on_connect() -> None:
    """No-op connect callback."""


async def _noop_on_disconnect(expected_disconnect: bool) -> None:
    """No-op disconnect callback."""


def _other_devices_records(count: int) -> list[RecordUpdate]:
    """Build PTR, A and AAAA updates for devices other than the one listening."""
    records: list[RecordUpdate] = []
    for i in range(count):
        records.append(
            RecordUpdate(
                DNSPointer(
                    "_esphomelib._tcp.local.",
                    _TYPE_PTR,
                    _CLASS_IN,
                    4500,
                    f"Other-Device-{i}._esphomelib._tcp.local.",
                ),
                None,
            )
        )
        records.append(
            RecordUpdate(
                DNSAddress(
                    f"Other-Device-{i}.local.",
                    _TYPE_A,
                    _CLASS_IN,
                    120,
                    ip_address(f"192.168.1.{i + 10}").packed,
                ),
                None,
            )
        )
        records.append(
            RecordUpdate(
                DNSAddress(
                    f"Other-Device-{i}.local.",
                    _TYPE_AAAA,
                    _CLASS_IN,
                    120,
                    ip_address(f"fe80::{i + 10:x}").packed,
                ),
                None,
            )
        )
    return records


def _host_packet(host: str, service: str, index: int) -> list[RecordUpdate]:
    """Build the records of one mDNS answer packet from host for service."""
    instance = f"{host}.{service}"
    target = f"{host}.local."
    records = (
        DNSPointer(service, _TYPE_PTR, _CLASS_IN, 4500, instance),
        DNSService(instance, _TYPE_SRV, _CLASS_IN, 120, 0, 0, 80, target),
        DNSText(instance, _TYPE_TXT, _CLASS_IN, 4500, b"\x05a=123"),
        DNSAddress(
            target,
            _TYPE_A,
            _CLASS_IN,
            120,
            ip_address(f"10.0.{index // 250}.{index % 250 + 1}").packed,
        ),
        DNSAddress(
            target,
            _TYPE_AAAA,
            _CLASS_IN,
            120,
            ip_address(f"fe80::{index + 1:x}").packed,
        ),
        DNSNsec(
            instance, _TYPE_NSEC, _CLASS_IN, 4500, instance, [_TYPE_TXT, _TYPE_SRV]
        ),
        DNSNsec(target, _TYPE_NSEC, _CLASS_IN, 120, target, [_TYPE_A, _TYPE_AAAA]),
    )
    return [RecordUpdate(record, None) for record in records]


def _registered_wake(dispatcher: ZeroconfRecordDispatcher, name: str) -> ReconnectLogic:
    """Build a started ReconnectLogic whose wake is registered on dispatcher."""
    rl = ReconnectLogic(
        client=APIClient(f"{name}.local", 6053, None),
        on_connect=_noop_on_connect,
        on_disconnect=_noop_on_disconnect,
        name=name,
    )
    rl._is_stopped = False
    dispatcher.add(rl._zc_wake)
    return rl


async def test_zeroconf_wake_non_matching_records(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark one offline device's listener scanning other devices' records."""
    dispatcher = ZeroconfRecordDispatcher(MagicMock())
    rl = _registered_wake(dispatcher, "mydevice")
    records = _other_devices_records(20)

    @benchmark
    def scan_records() -> None:
        dispatcher.async_update_records(None, 0.0, records)  # type: ignore[arg-type]

    assert rl._zc_wake._accept_records is True


async def test_zeroconf_wake_non_matching_records_100_devices(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 registered devices sharing one listener on foreign records."""
    dispatcher = ZeroconfRecordDispatcher(MagicMock())
    logics = [_registered_wake(dispatcher, f"mydevice-{i}") for i in range(100)]
    records = _other_devices_records(20)

    @benchmark
    def scan_records() -> None:
        dispatcher.async_update_records(None, 0.0, records)  # type: ignore[arg-type]

    assert all(rl._zc_wake._accept_records for rl in logics)


async def test_zeroconf_wake_matching_record_gate_closed(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark a matching record for a wake whose one-shot gate is closed."""
    dispatcher = ZeroconfRecordDispatcher(MagicMock())
    rl = _registered_wake(dispatcher, "Other-Device-3")
    rl._zc_wake._accept_records = False
    records = _other_devices_records(20)

    @benchmark
    def scan_records() -> None:
        dispatcher.async_update_records(None, 0.0, records)  # type: ignore[arg-type]

    assert rl._zc_wake._accept_records is False


async def test_zeroconf_dispatch_lan_traffic_100_devices(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 300 foreign hosts' answer packets against 100 registered devices."""
    dispatcher = ZeroconfRecordDispatcher(MagicMock())
    logics = [_registered_wake(dispatcher, f"mydevice-{i}") for i in range(100)]
    packets = [
        _host_packet(f"Foreign-{i}", LAN_SERVICES[i % len(LAN_SERVICES)], i)
        for i in range(300)
    ]

    @benchmark
    def dispatch_packets() -> None:
        for packet in packets:
            dispatcher.async_update_records(None, 0.0, packet)  # type: ignore[arg-type]

    assert all(rl._zc_wake._accept_records for rl in logics)


async def test_zeroconf_dispatch_connected_announce_burst(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark 100 connected devices each sending an announcement round 1s apart."""
    dispatcher = ZeroconfRecordDispatcher(MagicMock())
    logics = [_registered_wake(dispatcher, f"esp-{i}") for i in range(100)]
    for rl in logics:
        rl._probe_on_announce = True
        rl._connection_state = ReconnectLogicState.READY
    packets = [
        _host_packet(f"esp-{i}", "_esphomelib._tcp.local.", i) for i in range(100)
    ]
    now = 0.0

    @benchmark
    def dispatch_round() -> None:
        nonlocal now
        now += 1000.0
        for packet in packets:
            dispatcher.async_update_records(None, now, packet)  # type: ignore[arg-type]

    assert all(rl._zc_wake._last_packet_ms == now for rl in logics)
