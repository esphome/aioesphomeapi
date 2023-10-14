import asyncio
import socket
from typing import Optional

import pytest
from mock import MagicMock, patch

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi.api_pb2 import DeviceInfoResponse, HelloResponse
from aioesphomeapi.connection import APIConnection, ConnectionParams, ConnectionState
from aioesphomeapi.core import RequiresEncryptionAPIError
from aioesphomeapi.host_resolver import AddrInfo, IPv4Sockaddr


async def connect(conn: APIConnection, login: bool = True):
    """Wrapper for connection logic to do both parts."""
    await conn.start_connection()
    await conn.finish_connection(login=login)


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
        on_pkt=conn._process_packet,
        on_error=conn._report_fatal_error,
        client_info="mock",
        log_name="mock_device",
    )
    transport = MagicMock()
    protocol.connection_made(transport)
    return protocol


@pytest.mark.asyncio
async def test_connect(conn, resolve_host, socket_socket, event_loop):
    loop = asyncio.get_event_loop()
    protocol: Optional[APIPlaintextFrameHelper] = None
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
        protocol.data_received(
            bytes.fromhex(
                "003602080110091a216d6173746572617672656c61792028657"
                "370686f6d652076323032332e362e3329220d6d617374657261"
                "7672656c6179"
            )
        )
        protocol.data_received(
            bytes.fromhex(
                "005b0a120d6d6173746572617672656c61791a1130383a33413a"
                "46323a33453a35453a36302208323032332e362e332a154a756e"
                "20323820323032332c2031383a31323a3236320965737033322d"
                "65766250506209457370726573736966"
            )
        )

        await connect_task

    assert conn.is_connected


@pytest.mark.asyncio
async def test_requires_encryption_propagates(conn: APIConnection):
    loop = asyncio.get_event_loop()
    protocol = _get_mock_protocol(conn)
    with patch.object(loop, "create_connection") as create_connection:
        create_connection.return_value = (MagicMock(), protocol)

        conn._socket = MagicMock()
        await conn._connect_init_frame_helper()
        loop.call_soon(conn._frame_helper._ready_future.set_result, None)
        conn.connection_state = ConnectionState.CONNECTED

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
    protocol: Optional[APIPlaintextFrameHelper] = None
    transport = MagicMock()
    connected = asyncio.Event()

    def _create_mock_transport_protocol(create_func, **kwargs):
        nonlocal protocol
        protocol = create_func()
        protocol.connection_made(transport)
        connected.set()
        return transport, protocol

    def on_msg(msg):
        messages.append(msg)

    remove = conn.add_message_callback(on_msg, (HelloResponse, DeviceInfoResponse))
    transport = MagicMock()

    with patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()

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
    await connect_task
    assert conn.is_connected
    assert len(messages) == 2
    assert isinstance(messages[0], HelloResponse)
    assert isinstance(messages[1], DeviceInfoResponse)
    assert messages[1].name == "m5stackatomproxy"
    remove()
    await conn.force_disconnect()
    await asyncio.sleep(0)
