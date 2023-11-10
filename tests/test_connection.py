from __future__ import annotations

import asyncio
import logging
import socket
from datetime import timedelta
from typing import Any, Coroutine, Generator, Optional
from unittest.mock import AsyncMock

import pytest
from google.protobuf import message
from mock import MagicMock, patch

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.plain_text import _cached_varuint_to_bytes
from aioesphomeapi.api_pb2 import (
    ConnectResponse,
    DeviceInfoResponse,
    HelloResponse,
    PingRequest,
    PingResponse,
)
from aioesphomeapi.connection import APIConnection, ConnectionParams, ConnectionState
from aioesphomeapi.core import (
    MESSAGE_TYPE_TO_PROTO,
    APIConnectionError,
    HandshakeAPIError,
    InvalidAuthAPIError,
    RequiresEncryptionAPIError,
    TimeoutAPIError,
)
from aioesphomeapi.host_resolver import AddrInfo, IPv4Sockaddr

from .common import async_fire_time_changed, utcnow

PROTO_TO_MESSAGE_TYPE = {v: k for k, v in MESSAGE_TYPE_TO_PROTO.items()}


logging.getLogger("aioesphomeapi").setLevel(logging.DEBUG)


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
async def test_timeout_sending_message(
    conn: APIConnection,
    resolve_host: Coroutine[Any, Any, AddrInfo],
    socket_socket: Generator[Any, Any, None],
    event_loop: asyncio.AbstractEventLoop,
    caplog: pytest.LogCaptureFixture,
) -> None:
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

    transport = MagicMock()

    with patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()
        protocol.data_received(
            b'\x00@\x02\x08\x01\x10\x07\x1a(m5stackatomproxy (esphome v2023.1.0-dev)"\x10m'
            b"5stackatomproxy"
            b"\x00\x00$"
            b"\x00\x00\x04"
            b'\x00e\n\x12\x10m5stackatomproxy\x1a\x11E8:9F:6D:0A:68:E0"\x0c2023.1.0-d'
            b"ev*\x15Jan  7 2023, 13:19:532\x0cm5stack-atomX\x03b\tEspressif"
        )

    await connect_task

    with pytest.raises(TimeoutAPIError):
        await conn.send_messages_await_response_complex(
            (PingRequest(),), None, None, (PingResponse,), timeout=0
        )

    transport.reset_mock()
    with patch("aioesphomeapi.connection.DISCONNECT_RESPONSE_TIMEOUT", 0.0):
        await conn.disconnect()

    transport.write.assert_called_with(b"\x00\x00\x05")

    assert "disconnect request failed" in caplog.text
    assert " Timeout waiting for DisconnectResponse after 0.0s" in caplog.text


@pytest.mark.asyncio
async def test_disconnect_when_not_fully_connected(
    conn: APIConnection,
    resolve_host: Coroutine[Any, Any, AddrInfo],
    socket_socket: Generator[Any, Any, None],
    event_loop: asyncio.AbstractEventLoop,
    caplog: pytest.LogCaptureFixture,
) -> None:
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

    transport = MagicMock()

    with patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()

    # Only send the first part of the handshake
    # so we are stuck in the middle of the connection process
    protocol.data_received(
        b'\x00@\x02\x08\x01\x10\x07\x1a(m5stackatomproxy (esphome v2023.1.0-dev)"\x10m'
    )

    await asyncio.sleep(0)
    transport.reset_mock()

    with patch("aioesphomeapi.connection.DISCONNECT_CONNECT_TIMEOUT", 0.0), patch(
        "aioesphomeapi.connection.DISCONNECT_RESPONSE_TIMEOUT", 0.0
    ):
        await conn.disconnect()

    with pytest.raises(
        APIConnectionError,
        match="Timed out waiting to finish connect before disconnecting",
    ):
        await connect_task

    transport.write.assert_called_with(b"\x00\x00\x05")

    assert "disconnect request failed" in caplog.text
    assert " Timeout waiting for DisconnectResponse after 0.0s" in caplog.text


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
            task = asyncio.create_task(conn._connect_hello_login(login=True))
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


@pytest.mark.asyncio
async def test_start_connection_socket_error(
    conn: APIConnection, resolve_host, socket_socket
):
    """Test handling of socket error during start connection."""
    loop = asyncio.get_event_loop()

    with patch.object(loop, "create_connection", side_effect=OSError("Socket error")):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        with pytest.raises(APIConnectionError, match="Socket error"):
            await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_start_connection_times_out(
    conn: APIConnection, resolve_host, socket_socket
):
    """Test handling of start connection timing out."""
    loop = asyncio.get_event_loop()

    async def _mock_socket_connect(*args, **kwargs):
        await asyncio.sleep(500)

    with patch.object(loop, "sock_connect", side_effect=_mock_socket_connect), patch(
        "aioesphomeapi.connection.TCP_CONNECT_TIMEOUT", 0.0
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)

        async_fire_time_changed(utcnow() + timedelta(seconds=200))
        await asyncio.sleep(0)

    with pytest.raises(APIConnectionError, match="Timeout while connecting"):
        await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_start_connection_os_error(
    conn: APIConnection, resolve_host, socket_socket
):
    """Test handling of start connection has an OSError."""
    loop = asyncio.get_event_loop()

    with patch.object(loop, "sock_connect", side_effect=OSError("Socket error")):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        with pytest.raises(APIConnectionError, match="Socket error"):
            await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_start_connection_is_cancelled(
    conn: APIConnection, resolve_host, socket_socket
):
    """Test handling of start connection is cancelled."""
    loop = asyncio.get_event_loop()

    with patch.object(loop, "sock_connect", side_effect=asyncio.CancelledError):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        with pytest.raises(APIConnectionError, match="Starting connection cancelled"):
            await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_finish_connection_is_cancelled(
    conn: APIConnection, resolve_host, socket_socket
):
    """Test handling of finishing connection being cancelled."""
    loop = asyncio.get_event_loop()

    with patch.object(loop, "create_connection", side_effect=asyncio.CancelledError):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        with pytest.raises(APIConnectionError, match="Finishing connection cancelled"):
            await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_finish_connection_times_out(
    conn: APIConnection, resolve_host, socket_socket
):
    """Test handling of finish connection timing out."""
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
    await asyncio.sleep(0)

    async_fire_time_changed(utcnow() + timedelta(seconds=200))
    await asyncio.sleep(0)

    with pytest.raises(APIConnectionError, match="Hello timed out"):
        await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)

    assert not conn.is_connected
    remove()
    await conn.force_disconnect()
    await asyncio.sleep(0)


@pytest.mark.parametrize(
    ("exception_map"),
    [
        (OSError("Socket error"), HandshakeAPIError),
        (asyncio.TimeoutError, TimeoutAPIError),
        (asyncio.CancelledError, APIConnectionError),
    ],
)
@pytest.mark.asyncio
async def test_plaintext_connection_fails_handshake(
    conn: APIConnection,
    resolve_host: AsyncMock,
    socket_socket: MagicMock,
    exception_map: tuple[Exception, Exception],
) -> None:
    """Test that the frame helper is closed before the underlying socket.

    If we don't do this, asyncio will get confused and not release the socket.
    """
    loop = asyncio.get_event_loop()
    exception, raised_exception = exception_map
    protocol = _get_mock_protocol(conn)
    messages = []
    protocol: Optional[APIPlaintextFrameHelper] = None
    transport = MagicMock()
    connected = asyncio.Event()

    class APIPlaintextFrameHelperHandshakeException(APIPlaintextFrameHelper):
        """Plaintext frame helper that raises exception on handshake."""

        def perform_handshake(self, timeout: float) -> Coroutine[Any, Any, None]:
            raise exception

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

    with patch(
        "aioesphomeapi.connection.APIPlaintextFrameHelper",
        APIPlaintextFrameHelperHandshakeException,
    ), patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()

    assert conn._socket is not None
    assert conn._frame_helper is not None

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

    call_order = []

    def _socket_close_call():
        call_order.append("socket_close")

    def _frame_helper_close_call():
        call_order.append("frame_helper_close")

    with patch.object(
        conn._socket, "close", side_effect=_socket_close_call
    ), patch.object(
        conn._frame_helper, "close", side_effect=_frame_helper_close_call
    ), pytest.raises(
        raised_exception
    ):
        await asyncio.sleep(0)
        await connect_task

    # Ensure the frame helper is closed before the socket
    # so asyncio releases the socket
    assert call_order == ["frame_helper_close", "socket_close"]
    assert not conn.is_connected
    assert len(messages) == 2
    assert isinstance(messages[0], HelloResponse)
    assert isinstance(messages[1], DeviceInfoResponse)
    assert messages[1].name == "m5stackatomproxy"
    remove()
    await conn.force_disconnect()
    await asyncio.sleep(0)


def _generate_plaintext_packet(msg: bytes, type_: int) -> bytes:
    return (
        b"\0"
        + _cached_varuint_to_bytes(len(msg))
        + _cached_varuint_to_bytes(type_)
        + msg
    )


@pytest.mark.asyncio
async def test_connect_wrong_password(conn, resolve_host, socket_socket, event_loop):
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
        connect_task = asyncio.create_task(connect(conn, login=True))
        await connected.wait()
        hello_response: message.Message = HelloResponse()
        hello_response.api_version_major = 1
        hello_response.api_version_minor = 9
        hello_response.name = "fake"
        hello_msg = hello_response.SerializeToString()

        connect_response: message.Message = ConnectResponse()
        connect_response.invalid_password = True
        connect_msg = connect_response.SerializeToString()

        protocol.data_received(
            _generate_plaintext_packet(hello_msg, PROTO_TO_MESSAGE_TYPE[HelloResponse])
        )
        protocol.data_received(
            _generate_plaintext_packet(
                connect_msg, PROTO_TO_MESSAGE_TYPE[ConnectResponse]
            )
        )

        with pytest.raises(InvalidAuthAPIError):
            await connect_task

    assert not conn.is_connected


@pytest.mark.asyncio
async def test_connect_correct_password(conn, resolve_host, socket_socket, event_loop):
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
        connect_task = asyncio.create_task(connect(conn, login=True))
        await connected.wait()
        hello_response: message.Message = HelloResponse()
        hello_response.api_version_major = 1
        hello_response.api_version_minor = 9
        hello_response.name = "fake"
        hello_msg = hello_response.SerializeToString()

        connect_response: message.Message = ConnectResponse()
        connect_response.invalid_password = False
        connect_msg = connect_response.SerializeToString()

        protocol.data_received(
            _generate_plaintext_packet(hello_msg, PROTO_TO_MESSAGE_TYPE[HelloResponse])
        )
        protocol.data_received(
            _generate_plaintext_packet(
                connect_msg, PROTO_TO_MESSAGE_TYPE[ConnectResponse]
            )
        )

        await connect_task

    assert conn.is_connected
