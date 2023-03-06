import asyncio
import socket

import pytest
from mock import MagicMock, patch

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi.api_pb2 import DeviceInfoResponse, HelloResponse
from aioesphomeapi.connection import APIConnection, ConnectionParams, ConnectionState
from aioesphomeapi.core import RequiresEncryptionAPIError
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
    async def on_stop(expected_disconnect: bool) -> None:
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


def _get_mock_protocol(conn: APIConnection):
    protocol = APIPlaintextFrameHelper(
        on_pkt=conn._process_packet, on_error=conn._report_fatal_error
    )
    protocol._connected_event.set()
    protocol._transport = MagicMock()
    return protocol


@pytest.mark.asyncio
async def test_connect(conn, resolve_host, socket_socket, event_loop):
    loop = asyncio.get_event_loop()
    protocol = _get_mock_protocol(conn)
    with patch.object(event_loop, "sock_connect"), patch.object(
        loop, "create_connection", return_value=(MagicMock(), protocol)
    ), patch.object(conn, "_connect_start_ping"), patch.object(
        conn, "send_message_await_response", return_value=HelloResponse()
    ):
        await conn.connect(login=False)

    assert conn.is_connected


@pytest.mark.asyncio
async def test_requires_encryption_propagates(conn: APIConnection):
    loop = asyncio.get_event_loop()
    protocol = _get_mock_protocol(conn)
    with patch.object(loop, "create_connection") as create_connection, patch.object(
        protocol, "perform_handshake"
    ):
        create_connection.return_value = (MagicMock(), protocol)

        await conn._connect_init_frame_helper()
        conn._connection_state = ConnectionState.CONNECTED

        with pytest.raises(RequiresEncryptionAPIError):
            task = asyncio.create_task(conn._connect_hello())
            await asyncio.sleep(0)
            protocol.data_received(b"\x01\x00\x00")
            await task


@pytest.mark.asyncio
async def test_plaintext_connection(conn: APIConnection, resolve_host, socket_socket):
    """Test that a plaintext connection works."""
    loop = asyncio.get_event_loop()
    protocol = _get_mock_protocol(conn)
    messages = []

    def on_msg(msg):
        messages.append(msg)

    remove = conn.add_message_callback(on_msg, {HelloResponse, DeviceInfoResponse})
    transport = MagicMock()

    with patch.object(conn, "_connect_hello"), patch.object(
        loop, "sock_connect"
    ), patch.object(loop, "create_connection") as create_connection, patch.object(
        protocol, "perform_handshake"
    ):
        create_connection.return_value = (transport, protocol)
        await conn.connect(login=False)

    protocol.data_received(
        b'\x00@\x02\x08\x01\x10\x07\x1a(m5stackatomproxy (esphome v2023.1.0-dev)"\x10m'
    )
    protocol.data_received(b"5stackatomproxy")
    protocol.data_received(b"\x00\x00$")
    protocol.data_received(b"\x00\x00\x04")
    protocol.data_received(
        b'\x00e\n\x12\x10m5stackatomproxy\x1a\x11E8:9F:6D:0A:68:E0"\x0c2023.1.0-d'
    )
    protocol.data_received(
        b"ev*\x15Jan  7 2023, 13:19:532\x0cm5stack-atomX\x03b\tEspressif"
    )
    await asyncio.sleep(0)
    assert conn.is_connected
    assert len(messages) == 2
    assert isinstance(messages[0], HelloResponse)
    assert isinstance(messages[1], DeviceInfoResponse)
    assert messages[1].name == "m5stackatomproxy"
    remove()
    await conn.force_disconnect()
    await asyncio.sleep(0)
