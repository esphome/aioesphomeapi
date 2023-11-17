"""Test fixtures."""
from __future__ import annotations

import asyncio
import socket
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi.client import APIClient, ConnectionParams
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.host_resolver import AddrInfo, IPv4Sockaddr
from aioesphomeapi.zeroconf import ZeroconfManager

from .common import connect, send_plaintext_hello


@pytest.fixture
def resolve_host():
    with patch("aioesphomeapi.host_resolver.async_resolve_host") as func:
        func.return_value = AddrInfo(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            sockaddr=IPv4Sockaddr("10.0.0.512", 6052),
        )
        yield func


@pytest.fixture
def socket_socket():
    with patch("socket.socket") as func:
        yield func


@pytest.fixture
def connection_params() -> ConnectionParams:
    return ConnectionParams(
        address="fake.address",
        port=6052,
        password=None,
        client_info="Tests client",
        keepalive=15.0,
        zeroconf_manager=ZeroconfManager(),
        noise_psk=None,
        expected_name=None,
    )


@pytest.fixture
def conn(connection_params) -> APIConnection:
    async def on_stop(expected_disconnect: bool) -> None:
        pass

    return APIConnection(connection_params, on_stop)


@pytest_asyncio.fixture(name="plaintext_connect_task_no_login")
async def plaintext_connect_task_no_login(
    conn: APIConnection, resolve_host, socket_socket, event_loop
) -> tuple[APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task]:
    loop = asyncio.get_event_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    def _create_mock_transport_protocol(create_func, **kwargs):
        nonlocal protocol
        protocol = create_func()
        protocol.connection_made(transport)
        connected.set()
        return transport, protocol

    with patch.object(event_loop, "sock_connect"), patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()
        yield conn, transport, protocol, connect_task


@pytest_asyncio.fixture(name="plaintext_connect_task_with_login")
async def plaintext_connect_task_with_login(
    conn: APIConnection, resolve_host, socket_socket, event_loop
) -> tuple[APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task]:
    loop = asyncio.get_event_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    def _create_mock_transport_protocol(create_func, **kwargs):
        nonlocal protocol
        protocol = create_func()
        protocol.connection_made(transport)
        connected.set()
        return transport, protocol

    with patch.object(event_loop, "sock_connect"), patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ):
        connect_task = asyncio.create_task(connect(conn, login=True))
        await connected.wait()
        yield conn, transport, protocol, connect_task


@pytest_asyncio.fixture(name="api_client")
async def api_client(
    conn: APIConnection, resolve_host, socket_socket, event_loop
) -> tuple[APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper]:
    loop = asyncio.get_event_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()
    client = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )

    def _create_mock_transport_protocol(create_func, **kwargs):
        nonlocal protocol
        protocol = create_func()
        protocol.connection_made(transport)
        connected.set()
        return transport, protocol

    with patch.object(event_loop, "sock_connect"), patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()
        send_plaintext_hello(protocol)
        client._connection = conn
        await connect_task
        transport.reset_mock()
        yield client, conn, transport, protocol
