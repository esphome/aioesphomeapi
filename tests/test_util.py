import asyncio
import math
import sys

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
