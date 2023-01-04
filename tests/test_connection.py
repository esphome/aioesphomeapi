import asyncio
import socket

import pytest
from mock import AsyncMock, MagicMock, Mock, patch

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper, Packet
from aioesphomeapi.api_pb2 import ConnectResponse, HelloResponse
from aioesphomeapi.connection import APIConnection, ConnectionParams, ConnectionState
from aioesphomeapi.core import APIConnectionError, RequiresEncryptionAPIError
from aioesphomeapi.host_resolver import AddrInfo, IPv4Sockaddr


@pytest.fixture
def connection_params() -> ConnectionParams:
    return ConnectionParams(
        address="fake.address",
        port=6052,
        password=None,
        client_info="Tests client",
        keepalive=15.0,
        zeroconf_instance=None,
        noise_psk=None,
        expected_name=None,
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


def _get_mock_protocol():
    def _on_packet(pkt: Packet):
        pass

    def _on_error(exc: Exception):
        raise exc

    protocol = APIPlaintextFrameHelper(on_pkt=_on_packet, on_error=_on_error)
    protocol._connected_event.set()
    protocol._transport = MagicMock()
    return protocol


@pytest.mark.asyncio
async def test_connect(conn, resolve_host, socket_socket, event_loop):
    loop = asyncio.get_event_loop()
    protocol = _get_mock_protocol()
    with patch.object(event_loop, "sock_connect"), patch.object(
        loop, "create_connection", return_value=(MagicMock(), protocol)
    ), patch.object(conn, "_connect_start_ping"), patch.object(
        conn, "send_message_await_response", return_value=HelloResponse()
    ):
        await conn.connect(login=False)

    assert conn.is_connected


@pytest.mark.asyncio
async def test_requires_encryption_propagates(conn):
    loop = asyncio.get_event_loop()
    protocol = _get_mock_protocol()
    with patch.object(loop, "create_connection") as create_connection, patch.object(
        protocol, "perform_handshake"
    ):
        create_connection.return_value = (MagicMock(), protocol)

        await conn._connect_init_frame_helper()

        with pytest.raises(RequiresEncryptionAPIError):
            protocol.data_received(b"\x01\x00\x00")
            await conn._connect_hello()
