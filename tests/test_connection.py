import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from aioesphomeapi.api_pb2 import ConnectResponse, HelloResponse
from aioesphomeapi.connection import APIConnection, ConnectionParams
from aioesphomeapi.core import APIConnectionError
from aioesphomeapi.host_resolver import AddrInfo, IPv4Sockaddr


@pytest.fixture
def connection_params() -> ConnectionParams:
    return ConnectionParams(
        eventloop=asyncio.get_event_loop(),
        address="fake.address",
        port=6052,
        password=None,
        client_info="Tests client",
        keepalive=15.0,
        zeroconf_instance=None,
    )


@pytest.fixture
def conn(connection_params) -> APIConnection:
    async def on_stop():
        pass

    return APIConnection(connection_params, on_stop)


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


@pytest.mark.asyncio
async def test_connect(conn, resolve_host, socket_socket, event_loop):
    with patch.object(event_loop, "sock_connect"), patch(
        "asyncio.open_connection", return_value=(None, None)
    ), patch.object(conn, "run_forever"), patch.object(
        conn, "_start_ping"
    ), patch.object(
        conn, "send_message_await_response", return_value=HelloResponse()
    ):
        await conn.connect()

    assert conn.is_connected
