"""Benchmarks."""

import asyncio

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aioesphomeapi import APIConnection
from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi.client import APIClient


def test_sending_request(
    benchmark: BenchmarkFixture,
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    client, connection, transport, protocol = api_client

    @benchmark
    def send_request():
        client.light_command(1, True)
