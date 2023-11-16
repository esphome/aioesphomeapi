from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi.api_pb2 import (
    DeviceInfoResponse,
    HelloResponse,
    PingRequest,
    PingResponse,
)
from aioesphomeapi.connection import APIConnection, ConnectionState
from aioesphomeapi.core import (
    APIConnectionError,
    HandshakeAPIError,
    InvalidAuthAPIError,
    RequiresEncryptionAPIError,
    TimeoutAPIError,
)

from .common import (
    async_fire_time_changed,
    connect,
    send_plaintext_connect_response,
    send_plaintext_hello,
    utcnow,
)


def _get_mock_protocol(conn: APIConnection):
    protocol = APIPlaintextFrameHelper(
        connection=conn,
        client_info="mock",
        log_name="mock_device",
    )
    transport = MagicMock()
    protocol.connection_made(transport)
    return protocol


@pytest.mark.asyncio
async def test_connect(
    plaintext_connect_task_no_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ]
) -> None:
    """Test that a plaintext connection works."""
    conn, transport, protocol, connect_task = plaintext_connect_task_no_login
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
    plaintext_connect_task_no_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_no_login

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
    plaintext_connect_task_no_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_no_login

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
async def test_plaintext_connection(
    plaintext_connect_task_no_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that a plaintext connection works."""
    messages = []
    conn, transport, protocol, connect_task = plaintext_connect_task_no_login

    def on_msg(msg):
        messages.append(msg)

    remove = conn.add_message_callback(on_msg, (HelloResponse, DeviceInfoResponse))
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
    plaintext_connect_task_no_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test handling of finish connection timing out."""
    conn, transport, protocol, connect_task = plaintext_connect_task_no_login
    messages = []

    def on_msg(msg):
        messages.append(msg)

    remove = conn.add_message_callback(on_msg, (HelloResponse, DeviceInfoResponse))
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
    protocol: APIPlaintextFrameHelper | None = None
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


@pytest.mark.asyncio
async def test_connect_wrong_password(
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login

    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, True)

    with pytest.raises(InvalidAuthAPIError):
        await connect_task

    assert not conn.is_connected


@pytest.mark.asyncio
async def test_connect_correct_password(
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login

    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)

    await connect_task

    assert conn.is_connected
