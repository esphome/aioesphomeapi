"""Benchmarks for the shared mDNS wake listener."""

from ipaddress import ip_address

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]
from zeroconf import DNSAddress, DNSPointer, RecordUpdate
from zeroconf.const import _CLASS_IN, _TYPE_A, _TYPE_AAAA, _TYPE_PTR

from aioesphomeapi._zc_listener import ZeroconfRecordDispatcher
from aioesphomeapi.client import APIClient
from aioesphomeapi.reconnect_logic import ReconnectLogic


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
    dispatcher = ZeroconfRecordDispatcher()
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
    dispatcher = ZeroconfRecordDispatcher()
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
    dispatcher = ZeroconfRecordDispatcher()
    rl = _registered_wake(dispatcher, "Other-Device-3")
    rl._zc_wake._accept_records = False
    records = _other_devices_records(20)

    @benchmark
    def scan_records() -> None:
        dispatcher.async_update_records(None, 0.0, records)  # type: ignore[arg-type]

    assert rl._zc_wake._accept_records is False
