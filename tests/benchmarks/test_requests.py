"""Benchmarks."""

import asyncio

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aioesphomeapi import APIConnection
from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.client import APIClient


def test_sending_light_command_request_with_bool(
    benchmark: BenchmarkFixture,
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    client, connection, _transport, _protocol = api_client

    connection._frame_helper._writelines = lambda lines: None

    @benchmark
    def send_request():
        client.light_command(1, True)


def test_sending_empty_light_command_request(
    benchmark: BenchmarkFixture,
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
) -> None:
    client, connection, _transport, _protocol = api_client

    connection._frame_helper._writelines = lambda lines: None

    @benchmark
    def send_request():
        client.light_command(1)
