"""Test fixtures."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import replace
from functools import partial
from typing import Callable
from unittest.mock import MagicMock, create_autospec, patch

import pytest
import pytest_asyncio

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi.client import APIClient, ConnectionParams
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.host_resolver import AddrInfo, IPv4Sockaddr
from aioesphomeapi.zeroconf import ZeroconfManager

from .common import (
    connect,
    connect_client,
    get_mock_async_zeroconf,
    send_plaintext_hello,
)

KEEP_ALIVE_INTERVAL = 15.0


class PatchableAPIConnection(APIConnection):
    pass


@pytest.fixture
def async_zeroconf():
    return get_mock_async_zeroconf()


@pytest.fixture
def resolve_host():
    with patch("aioesphomeapi.host_resolver.async_resolve_host") as func:
        func.return_value = [
            AddrInfo(
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
                sockaddr=IPv4Sockaddr("10.0.0.512", 6052),
            )
        ]
        yield func


@pytest.fixture
def patchable_api_client() -> APIClient:
    class PatchableAPIClient(APIClient):
        pass

    cli = PatchableAPIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
    )
    return cli


def get_mock_connection_params() -> ConnectionParams:
    return ConnectionParams(
        addresses=["fake.address"],
        port=6052,
        password=None,
        client_info="Tests client",
        keepalive=KEEP_ALIVE_INTERVAL,
        zeroconf_manager=ZeroconfManager(),
        noise_psk=None,
        expected_name=None,
    )


@pytest.fixture
def connection_params(event_loop: asyncio.AbstractEventLoop) -> ConnectionParams:
    return get_mock_connection_params()


def mock_on_stop(expected_disconnect: bool) -> None:
    pass


@pytest.fixture
def conn(
    event_loop: asyncio.AbstractEventLoop, connection_params: ConnectionParams
) -> APIConnection:
    return PatchableAPIConnection(connection_params, mock_on_stop, True, None)


@pytest.fixture
def conn_with_password(
    event_loop: asyncio.AbstractEventLoop, connection_params: ConnectionParams
) -> APIConnection:
    connection_params = replace(connection_params, password="password")
    return PatchableAPIConnection(connection_params, mock_on_stop, True, None)


@pytest.fixture
def noise_conn(
    event_loop: asyncio.AbstractEventLoop, connection_params: ConnectionParams
) -> APIConnection:
    connection_params = replace(
        connection_params, noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc="
    )
    return PatchableAPIConnection(connection_params, mock_on_stop, True, None)


@pytest.fixture
def conn_with_expected_name(
    event_loop: asyncio.AbstractEventLoop, connection_params: ConnectionParams
) -> APIConnection:
    connection_params = replace(connection_params, expected_name="test")
    return PatchableAPIConnection(connection_params, mock_on_stop, True, None)


@pytest.fixture()
def aiohappyeyeballs_start_connection(event_loop: asyncio.AbstractEventLoop):
    with patch("aioesphomeapi.connection.aiohappyeyeballs.start_connection") as func:
        mock_socket = create_autospec(socket.socket, spec_set=True, instance=True)
        mock_socket.type = socket.SOCK_STREAM
        mock_socket.fileno.return_value = 1
        mock_socket.getpeername.return_value = ("10.0.0.512", 323)
        func.return_value = mock_socket
        yield func


def _create_mock_transport_protocol(
    transport: asyncio.Transport,
    connected: asyncio.Event,
    create_func: Callable[[], APIPlaintextFrameHelper],
    **kwargs,
) -> tuple[asyncio.Transport, APIPlaintextFrameHelper]:
    protocol: APIPlaintextFrameHelper = create_func()
    protocol.connection_made(transport)
    connected.set()
    return transport, protocol


@pytest_asyncio.fixture(name="plaintext_connect_task_no_login")
async def plaintext_connect_task_no_login(
    conn: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> tuple[APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task]:
    loop = asyncio.get_event_loop()
    transport = MagicMock()
    connected = asyncio.Event()

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()
        yield conn, transport, conn._frame_helper, connect_task


@pytest_asyncio.fixture(name="plaintext_connect_task_expected_name")
async def plaintext_connect_task_no_login_with_expected_name(
    conn_with_expected_name: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> tuple[APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task]:
    event_loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()

    with patch.object(
        event_loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        connect_task = asyncio.create_task(
            connect(conn_with_expected_name, login=False)
        )
        await connected.wait()
        yield conn_with_expected_name, transport, conn_with_expected_name._frame_helper, connect_task


@pytest_asyncio.fixture(name="plaintext_connect_task_with_login")
async def plaintext_connect_task_with_login(
    conn_with_password: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> tuple[APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task]:
    transport = MagicMock()
    connected = asyncio.Event()
    event_loop = asyncio.get_running_loop()

    with patch.object(
        event_loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        connect_task = asyncio.create_task(connect(conn_with_password, login=True))
        await connected.wait()
        yield conn_with_password, transport, conn_with_password._frame_helper, connect_task


@pytest_asyncio.fixture(name="api_client")
async def api_client(
    resolve_host, aiohappyeyeballs_start_connection
) -> tuple[APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper]:
    event_loop = asyncio.get_running_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()
    client = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )

    with (
        patch.object(
            event_loop,
            "create_connection",
            side_effect=partial(_create_mock_transport_protocol, transport, connected),
        ),
        patch("aioesphomeapi.client.APIConnection", PatchableAPIConnection),
    ):
        connect_task = asyncio.create_task(connect_client(client, login=False))
        await connected.wait()
        conn = client._connection
        protocol = conn._frame_helper
        send_plaintext_hello(protocol)
        await connect_task
        transport.reset_mock()
        yield client, conn, transport, protocol
