import math

import pytest

from aioesphomeapi import util


@pytest.mark.parametrize(
    "input, output",
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
