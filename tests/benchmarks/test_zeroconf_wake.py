"""Benchmarks for the mDNS wake listener of an offline device."""

from ipaddress import ip_address

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]
from zeroconf import DNSAddress, DNSPointer, RecordUpdate
from zeroconf.const import _CLASS_IN, _TYPE_A, _TYPE_AAAA, _TYPE_PTR

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


async def test_zeroconf_wake_non_matching_records(
    benchmark: BenchmarkFixture,
) -> None:
    """Benchmark an offline device's listener scanning other devices' records."""
    cli = APIClient("mydevice.local", 6053, None)
    rl = ReconnectLogic(
        client=cli,
        on_connect=_noop_on_connect,
        on_disconnect=_noop_on_disconnect,
        name="mydevice",
    )
    rl._is_stopped = False
    wake = rl._zc_wake
    records = _other_devices_records(20)

    @benchmark
    def scan_records() -> None:
        wake.async_update_records(None, 0.0, records)  # type: ignore[arg-type]

    assert wake._accept_records is True
