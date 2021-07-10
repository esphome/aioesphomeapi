import pytest

from aioesphomeapi import util

VARUINT_TESTCASES = [
    (0, b"\x00"),
    (42, b"\x2a"),
    (127, b"\x7f"),
    (128, b"\x80\x01"),
    (300, b"\xac\x02"),
    (65536, b"\x80\x80\x04"),
]


@pytest.mark.parametrize("val, encoded", VARUINT_TESTCASES)
def test_varuint_to_bytes(val, encoded):
    assert util.varuint_to_bytes(val) == encoded


@pytest.mark.parametrize("val, encoded", VARUINT_TESTCASES)
def test_bytes_to_varuint(val, encoded):
    assert util.bytes_to_varuint(encoded) == val
