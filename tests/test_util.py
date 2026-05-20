import asyncio
import math
import sys

import pytest

from aioesphomeapi import util
from aioesphomeapi.util import address_is_local, build_log_name, is_ip_address


@pytest.mark.parametrize(
    ("input", "output"),
    [
        (0, 0),
        (float("inf"), float("inf")),
        (float("-inf"), float("-inf")),
        (0.1, 0.1),
        (-0.0, -0.0),
        (0.10000000149011612, 0.1),
        (1, 1),
        (-1, -1),
        (-0.10000000149011612, -0.1),
        (-152198557936981706463557226105667584, -152198600000000000000000000000000000),
        (-0.0030539485160261, -0.003053949),
        (0.5, 0.5),
        (0.0000000000000019, 0.0000000000000019),
    ],
)
def test_fix_float_single_double_conversion(input, output):
    assert util.fix_float_single_double_conversion(input) == output


def test_fix_float_single_double_conversion_nan():
    assert math.isnan(util.fix_float_single_double_conversion(float("nan")))


@pytest.mark.skipif(sys.version_info < (3, 12), reason="Test requires Python 3.12+")
async def test_create_eager_task_312() -> None:
    """Test create_eager_task schedules a task eagerly in the event loop.

    For Python 3.12+, the task is scheduled eagerly in the event loop.
    """
    events = []

    async def _normal_task():
        events.append("normal")

    async def _eager_task():
        events.append("eager")

    task1 = util.create_eager_task(_eager_task())
    task2 = asyncio.create_task(_normal_task())

    assert events == ["eager"]

    await asyncio.sleep(0)
    assert events == ["eager", "normal"]
    await task1
    await task2


@pytest.mark.skipif(sys.version_info >= (3, 12), reason="Test requires < Python 3.12")
async def test_create_eager_task_pre_312() -> None:
    """Test create_eager_task schedules a task in the event loop.

    For older python versions, the task is scheduled normally.
    """
    events = []

    async def _normal_task():
        events.append("normal")

    async def _eager_task():
        events.append("eager")

    task1 = util.create_eager_task(_eager_task())
    task2 = asyncio.create_task(_normal_task())

    assert events == []

    await asyncio.sleep(0)
    assert events == ["eager", "normal"]
    await task1
    await task2


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        # IPv4 bare and with port.
        ("192.168.1.10", True),
        ("192.168.1.10:6053", True),
        ("10.0.0.1", True),
        ("255.255.255.255", True),
        # Bare IPv6.
        ("::1", True),
        ("::", True),
        ("2001:db8::1", True),
        ("fe80::1", True),
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True),
        # Bracketed IPv6 with optional port.
        ("[::1]", True),
        ("[::1]:6053", True),
        ("[2001:db8::1]:6053", True),
        # Hostnames and other non-IP strings.
        ("myesp", False),
        ("myesp.local", False),
        ("host.example.com", False),
        ("host:6053", False),
        ("", False),
        # Malformed bracketed forms.
        ("[::1", False),
        ("[notanip]", False),
        ("[::1]junk", False),
        ("[::1]]", False),
        # None.
        (None, False),
    ],
)
def test_is_ip_address(address: str | None, expected: bool) -> None:
    assert is_ip_address(address) is expected


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("myesp.local", True),
        ("myesp.local.", True),
        # mDNS / DNS names are case-insensitive (RFC 6762 §16, RFC 4343).
        ("MyESP.LOCAL", True),
        ("myesp.Local", True),
        ("MYESP.LOCAL.", True),
        ("myesp", False),
        ("myesp.localdomain", False),
        ("host.example.com", False),
        ("", False),
    ],
)
def test_address_is_local(address: str, expected: bool) -> None:
    assert address_is_local(address) is expected


@pytest.mark.parametrize(
    ("name", "addresses", "connected_address", "expected"),
    [
        # Bare hostname only.
        ("myesp", ["myesp"], None, "myesp"),
        (None, ["myesp"], None, "myesp"),
        # mDNS .local only.
        (None, ["myesp.local"], None, "myesp"),
        ("myesp", ["myesp.local"], None, "myesp.local"),
        # IP only.
        (None, ["192.168.1.10"], None, "192.168.1.10"),
        ("myesp", ["192.168.1.10"], None, "myesp @ 192.168.1.10"),
        # Connected address provided.
        ("myesp", ["192.168.1.10"], "192.168.1.10", "myesp @ 192.168.1.10"),
        (None, ["10.0.0.1"], "192.168.1.10", "192.168.1.10"),
        ("myesp", ["myesp"], "192.168.1.10", "myesp @ 192.168.1.10"),
        # Multiple addresses: name derived from one, IP becomes preferred.
        (None, ["myesp", "192.168.1.10"], None, "myesp @ 192.168.1.10"),
        (None, ["myesp.local", "192.168.1.10"], None, "myesp @ 192.168.1.10"),
        (None, ["192.168.1.10", "myesp.local"], None, "myesp @ 192.168.1.10"),
        # Case-insensitive prefix match between name and .local address.
        ("myesp", ["MYESP.local"], None, "MYESP.local"),
        ("MYESP", ["myesp.local"], None, "myesp.local"),
        # Bare hostname overrides supplied name (loop reassigns).
        ("alice", ["bob"], None, "bob"),
        # Bracketed IPv6 as preferred address.
        ("myesp", ["[::1]:6053"], None, "myesp @ [::1]:6053"),
        (None, ["[::1]:6053"], None, "[::1]:6053"),
    ],
)
def test_build_log_name(
    name: str | None,
    addresses: list[str],
    connected_address: str | None,
    expected: str,
) -> None:
    assert build_log_name(name, addresses, connected_address) == expected
