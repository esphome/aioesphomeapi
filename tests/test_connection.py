from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import timedelta
from functools import partial
import logging
import socket
from typing import Callable, cast
from unittest.mock import AsyncMock, MagicMock, call, create_autospec, patch

from google.protobuf import message
import pytest

from aioesphomeapi import APIClient
from aioesphomeapi._frame_helper.packets import _cached_varuint_to_bytes
from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.api_pb2 import (
    DeviceInfoResponse,
    DisconnectRequest,
    HelloResponse,
    PingRequest,
    PingResponse,
    TextSensorStateResponse,
)
from aioesphomeapi.connection import APIConnection, ConnectionParams, ConnectionState
from aioesphomeapi.core import (
    APIConnectionCancelledError,
    APIConnectionError,
    ConnectionNotEstablishedAPIError,
    HandshakeAPIError,
    InvalidAuthAPIError,
    ReadFailedAPIError,
    RequiresEncryptionAPIError,
    ResolveAPIError,
    SocketAPIError,
    SocketClosedAPIError,
    TimeoutAPIError,
)

from .common import (
    KEEP_ALIVE_INTERVAL,
    _create_mock_transport_protocol,
    async_fire_time_changed,
    connect,
    connect_client,
    generate_plaintext_packet,
    get_mock_protocol,
    mock_data_received,
    send_ping_request,
    send_ping_response,
    send_plaintext_connect_response,
    send_plaintext_hello,
    utcnow,
)

KEEP_ALIVE_TIMEOUT_RATIO = 4.5


async def test_connect(
    plaintext_connect_task_no_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    """Test that a plaintext connection works."""
    conn, transport, protocol, connect_task = plaintext_connect_task_no_login
    mock_data_received(
        protocol,
        bytes.fromhex(
            "003602080110091a216d6173746572617672656c61792028657"
            "370686f6d652076323032332e362e3329220d6d617374657261"
            "7672656c6179"
        ),
    )
    mock_data_received(
        protocol,
        bytes.fromhex(
            "005b0a120d6d6173746572617672656c61791a1130383a33413a"
            "46323a33453a35453a36302208323032332e362e332a154a756e"
            "20323820323032332c2031383a31323a3236320965737033322d"
            "65766250506209457370726573736966"
        ),
    )
    await connect_task
    assert conn.is_connected


async def test_timeout_sending_message(
    plaintext_connect_task_no_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_no_login

    mock_data_received(
        protocol,
        b'\x00@\x02\x08\x01\x10\x07\x1a(m5stackatomproxy (esphome v2023.1.0-dev)"\x10m'
        b"5stackatomproxy"
        b"\x00\x00$"
        b"\x00\x00\x04"
        b'\x00e\n\x12\x10m5stackatomproxy\x1a\x11E8:9F:6D:0A:68:E0"\x0c2023.1.0-d'
        b"ev*\x15Jan  7 2023, 13:19:532\x0cm5stack-atomX\x03b\tEspressif",
    )

    await connect_task

    with pytest.raises(TimeoutAPIError):
        await conn.send_messages_await_response_complex(
            (PingRequest(),), None, None, (PingResponse,), 0
        )

    transport.reset_mock()
    with patch("aioesphomeapi.connection.DISCONNECT_RESPONSE_TIMEOUT", 0.0):
        await conn.disconnect()

    transport.writelines.assert_called_with([b"\x00", b"\x00", b"\x05"])

    assert "disconnect request failed" in caplog.text
    assert " Timeout waiting for DisconnectResponse after 0.0s" in caplog.text


async def test_disconnect_when_not_fully_connected(
    plaintext_connect_task_no_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_no_login

    # Only send the first part of the handshake
    # so we are stuck in the middle of the connection process
    mock_data_received(
        protocol,
        b'\x00@\x02\x08\x01\x10\x07\x1a(m5stackatomproxy (esphome v2023.1.0-dev)"\x10m',
    )

    await asyncio.sleep(0)
    transport.reset_mock()

    with (
        patch("aioesphomeapi.connection.DISCONNECT_CONNECT_TIMEOUT", 0.0),
        patch("aioesphomeapi.connection.DISCONNECT_RESPONSE_TIMEOUT", 0.0),
    ):
        await conn.disconnect()

    with pytest.raises(
        APIConnectionError,
        match="Timed out waiting to finish connect before disconnecting",
    ):
        await connect_task

    transport.writelines.assert_called_with([b"\x00", b"\x00", b"\x05"])

    assert "disconnect request failed" in caplog.text
    assert " Timeout waiting for DisconnectResponse after 0.0s" in caplog.text


async def test_requires_encryption_propagates(conn: APIConnection):
    loop = asyncio.get_running_loop()
    protocol = get_mock_protocol(conn)
    with patch.object(loop, "create_connection") as create_connection:
        create_connection.return_value = (MagicMock(), protocol)

        conn._socket = MagicMock()
        await conn._connect_init_frame_helper()
        loop.call_soon(conn._frame_helper.ready_future.set_result, None)
        conn.connection_state = ConnectionState.CONNECTED

        with pytest.raises(RequiresEncryptionAPIError):
            task = asyncio.create_task(conn._connect_hello_login(login=True))
            await asyncio.sleep(0)
            mock_data_received(protocol, b"\x01\x00\x00")
            await task

    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert isinstance(conn._fatal_exception, RequiresEncryptionAPIError)
    conn.force_disconnect()
    assert isinstance(conn._fatal_exception, RequiresEncryptionAPIError)
    conn.report_fatal_error(Exception("test"))
    assert isinstance(conn._fatal_exception, RequiresEncryptionAPIError)


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
    mock_data_received(
        protocol,
        b'\x00@\x02\x08\x01\x10\x07\x1a(m5stackatomproxy (esphome v2023.1.0-dev)"\x10m',
    )
    mock_data_received(protocol, b"5stackatomproxy")
    mock_data_received(protocol, b"\x00\x00$")
    mock_data_received(protocol, b"\x00\x00\x04")
    mock_data_received(
        protocol,
        b'\x00e\n\x12\x10m5stackatomproxy\x1a\x11E8:9F:6D:0A:68:E0"\x0c2023.1.0-d',
    )
    mock_data_received(
        protocol, b"ev*\x15Jan  7 2023, 13:19:532\x0cm5stack-atomX\x03b\tEspressif"
    )
    await asyncio.sleep(0)
    await connect_task
    assert conn.is_connected
    assert len(messages) == 2
    assert isinstance(messages[0], HelloResponse)
    assert isinstance(messages[1], DeviceInfoResponse)
    assert messages[1].name == "m5stackatomproxy"
    remove()
    conn.force_disconnect()
    await asyncio.sleep(0)


async def test_start_connection_socket_error(
    conn: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection,
):
    """Test handling of socket error during start connection."""
    loop = asyncio.get_running_loop()

    with patch.object(loop, "create_connection", side_effect=OSError("Socket error")):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        with pytest.raises(APIConnectionError, match="Socket error"):
            await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


async def test_start_connection_cannot_increase_recv_buffer(
    conn: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection: MagicMock,
    caplog: pytest.LogCaptureFixture,
):
    """Test failing to increase the recv buffer."""
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    tried_sizes = []

    def _setsockopt(*args, **kwargs):
        if args[0] == socket.SOL_SOCKET and args[1] == socket.SO_RCVBUF:
            size = args[2]
            tried_sizes.append(size)
            raise OSError("Socket error")

    mock_socket: socket.socket = create_autospec(
        socket.socket, spec_set=True, instance=True
    )
    mock_socket.type = socket.SOCK_STREAM
    mock_socket.fileno.return_value = 1
    mock_socket.getpeername.return_value = ("10.0.0.512", 323)
    mock_socket.setsockopt = _setsockopt
    with suppress(AttributeError):
        mock_socket.sendmsg.side_effect = OSError("Socket error")
    mock_socket.send.side_effect = OSError("Socket error")
    mock_socket.sendto.side_effect = OSError("Socket error")

    aiohappyeyeballs_start_connection.return_value = mock_socket

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        await connected.wait()
        protocol = conn._frame_helper
        send_plaintext_hello(protocol)
        await connect_task

    assert "Unable to increase the socket receive buffer size to 131072" in caplog.text
    assert tried_sizes == [2097152, 1048576, 524288, 262144, 131072]

    # Failure to increase the buffer size should not cause the connection to fail
    assert conn.is_connected
    conn.force_disconnect()


async def test_start_connection_can_only_increase_buffer_size_to_262144(
    conn: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection: MagicMock,
    caplog: pytest.LogCaptureFixture,
):
    """Test the receive buffer can only be increased to 262144."""
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    tried_sizes = []

    def _setsockopt(*args, **kwargs):
        if args[0] == socket.SOL_SOCKET and args[1] == socket.SO_RCVBUF:
            size = args[2]
            tried_sizes.append(size)
            if size != 262144:
                raise OSError("Socket error")

    mock_socket: socket.socket = create_autospec(
        socket.socket, spec_set=True, instance=True
    )
    mock_socket.type = socket.SOCK_STREAM
    mock_socket.fileno.return_value = 1
    mock_socket.getpeername.return_value = ("10.0.0.512", 323)
    mock_socket.setsockopt = _setsockopt
    with suppress(AttributeError):
        mock_socket.sendmsg.side_effect = OSError("Socket error")
    mock_socket.send.side_effect = OSError("Socket error")
    mock_socket.sendto.side_effect = OSError("Socket error")
    aiohappyeyeballs_start_connection.return_value = mock_socket

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        await connected.wait()
        protocol = conn._frame_helper
        send_plaintext_hello(protocol)
        await connect_task

    assert "Unable to increase the socket receive buffer size" not in caplog.text
    assert tried_sizes == [2097152, 1048576, 524288, 262144]

    # Failure to increase the buffer size should not cause the connection to fail
    assert conn.is_connected
    conn.force_disconnect()


async def test_start_connection_times_out(
    conn: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection,
):
    """Test handling of start connection timing out."""
    asyncio.get_running_loop()

    async def _mock_socket_connect(*args, **kwargs):
        await asyncio.sleep(500)

    with (
        patch(
            "aioesphomeapi.connection.aiohappyeyeballs.start_connection",
            side_effect=_mock_socket_connect,
        ),
        patch("aioesphomeapi.connection.TCP_CONNECT_TIMEOUT", 0.0),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)

        async_fire_time_changed(utcnow() + timedelta(seconds=200))
        await asyncio.sleep(0)

    with pytest.raises(APIConnectionError, match="Timeout while connecting"):
        await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


async def test_start_connection_os_error(conn: APIConnection, resolve_host):
    """Test handling of start connection has an OSError."""
    asyncio.get_running_loop()

    with patch(
        "aioesphomeapi.connection.aiohappyeyeballs.start_connection",
        side_effect=OSError("Socket error"),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        with pytest.raises(APIConnectionError, match="Socket error"):
            await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


async def test_start_connection_is_cancelled(conn: APIConnection, resolve_host):
    """Test handling of start connection is cancelled."""
    asyncio.get_running_loop()

    with patch(
        "aioesphomeapi.connection.aiohappyeyeballs.start_connection",
        side_effect=asyncio.CancelledError,
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        with pytest.raises(APIConnectionError, match="Starting connection cancelled"):
            await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


async def test_finish_connection_is_cancelled(
    conn: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection,
):
    """Test handling of finishing connection being cancelled."""
    loop = asyncio.get_running_loop()

    with patch.object(loop, "create_connection", side_effect=asyncio.CancelledError):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await asyncio.sleep(0)
        with pytest.raises(APIConnectionError, match="Finishing connection cancelled"):
            await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)


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
    mock_data_received(
        protocol,
        b'\x00@\x02\x08\x01\x10\x07\x1a(m5stackatomproxy (esphome v2023.1.0-dev)"\x10m',
    )
    await asyncio.sleep(0)

    async_fire_time_changed(utcnow() + timedelta(seconds=200))
    await asyncio.sleep(0)

    with pytest.raises(
        APIConnectionError, match="Timeout waiting for HelloResponse after 30.0s"
    ):
        await connect_task

    async_fire_time_changed(utcnow() + timedelta(seconds=600))
    await asyncio.sleep(0)

    assert not conn.is_connected
    remove()
    conn.force_disconnect()
    await asyncio.sleep(0)


@pytest.mark.parametrize(
    ("exception_map"),
    [
        (OSError("Socket error"), HandshakeAPIError),
        (APIConnectionError, APIConnectionError),
        (SocketClosedAPIError, SocketClosedAPIError),
        (asyncio.TimeoutError, TimeoutAPIError),
        (asyncio.CancelledError, APIConnectionError),
    ],
)
async def test_plaintext_connection_fails_handshake(
    conn: APIConnection,
    resolve_host: AsyncMock,
    aiohappyeyeballs_start_connection: MagicMock,
    exception_map: tuple[Exception, Exception],
) -> None:
    """Test that the frame helper is closed before the underlying socket.

    If we don't do this, asyncio will get confused and not release the socket.
    """
    loop = asyncio.get_running_loop()
    exception, raised_exception = exception_map
    messages = []
    transport = MagicMock()
    connected = asyncio.Event()

    class APIPlaintextFrameHelperHandshakeException(APIPlaintextFrameHelper):
        """Plaintext frame helper that raises exception on handshake."""

    def _create_failing_mock_transport_protocol(
        transport: asyncio.Transport,
        connected: asyncio.Event,
        create_func: Callable[[], APIPlaintextFrameHelper],
        **kwargs,
    ) -> tuple[asyncio.Transport, APIPlaintextFrameHelperHandshakeException]:
        protocol: APIPlaintextFrameHelperHandshakeException = create_func()
        protocol._transport = cast(asyncio.Transport, transport)
        protocol._writelines = transport.writelines
        protocol.ready_future.set_exception(exception)
        connected.set()
        return transport, protocol

    def on_msg(msg):
        messages.append(msg)

    remove = conn.add_message_callback(on_msg, (HelloResponse, DeviceInfoResponse))
    transport = MagicMock()

    call_order = []

    def _socket_close_call():
        call_order.append("socket_close")

    def _frame_helper_close_call():
        call_order.append("frame_helper_close")

    async def _do_finish_connect(self, *args, **kwargs):
        try:
            await conn._connect_init_frame_helper()
        finally:
            conn._socket.close = _socket_close_call
            conn._frame_helper.close = _frame_helper_close_call

    with (
        patch(
            "aioesphomeapi.connection.APIPlaintextFrameHelper",
            APIPlaintextFrameHelperHandshakeException,
        ),
        patch.object(
            loop,
            "create_connection",
            side_effect=partial(
                _create_failing_mock_transport_protocol, transport, connected
            ),
        ),
        patch.object(conn, "_do_finish_connect", _do_finish_connect),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()

    with (
        pytest.raises(raised_exception),
    ):
        await asyncio.sleep(0)
        await connect_task

    # Ensure the frame helper is closed before the socket
    # so asyncio releases the socket
    assert call_order == ["frame_helper_close", "socket_close"]
    assert not conn.is_connected
    remove()
    conn.force_disconnect()
    await asyncio.sleep(0)


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


async def test_connect_wrong_version(
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login

    send_plaintext_hello(protocol, 3, 2)
    send_plaintext_connect_response(protocol, False)

    with pytest.raises(APIConnectionError, match="Incompatible API version"):
        await connect_task

    assert conn.is_connected is False


async def test_connect_wrong_name(
    plaintext_connect_task_expected_name: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_expected_name
    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)

    with pytest.raises(
        APIConnectionError,
        match="Expected 'test' but server sent a different name: 'fake'",
    ):
        await connect_task

    assert conn.is_connected is False


async def test_force_disconnect_fails(
    caplog: pytest.LogCaptureFixture,
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login

    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)

    await connect_task
    assert conn.is_connected

    with patch.object(protocol, "_writelines", side_effect=OSError):
        conn.force_disconnect()
    assert "Failed to send (forced) disconnect request" in caplog.text
    await asyncio.sleep(0)


@pytest.mark.parametrize(
    ("exception_map"),
    [
        (OSError("original message"), ReadFailedAPIError),
        (APIConnectionError("original message"), APIConnectionError),
        (SocketClosedAPIError("original message"), SocketClosedAPIError),
    ],
)
async def test_connection_lost_while_connecting(
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
    exception_map: tuple[Exception, Exception],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login

    exception, raised_exception = exception_map
    protocol.connection_lost(exception)

    with pytest.raises(raised_exception, match="original message"):
        await connect_task

    assert not conn.is_connected


@pytest.mark.parametrize(
    ("exception_map"),
    [
        (OSError("original message"), SocketAPIError),
        (APIConnectionError("original message"), APIConnectionError),
        (SocketClosedAPIError("original message"), SocketClosedAPIError),
    ],
)
async def test_connection_error_during_hello(
    conn: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection,
    exception_map: tuple[Exception, Exception],
) -> None:
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    exception, raised_exception = exception_map

    with (
        patch.object(
            loop,
            "create_connection",
            side_effect=partial(_create_mock_transport_protocol, transport, connected),
        ),
        patch.object(conn, "_connect_hello_login", side_effect=exception),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()

    with pytest.raises(raised_exception, match="original message"):
        await connect_task

    assert not conn.is_connected


@pytest.mark.parametrize(
    ("exception_map"),
    [
        (OSError("original message"), APIConnectionCancelledError),
        (APIConnectionError("original message"), APIConnectionError),
        (SocketClosedAPIError("original message"), SocketClosedAPIError),
    ],
)
async def test_connection_cancelled_during_hello(
    conn: APIConnection,
    resolve_host,
    aiohappyeyeballs_start_connection,
    exception_map: tuple[Exception, Exception],
) -> None:
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    exception, raised_exception = exception_map

    async def _mock_frame_helper_error(*args, **kwargs):
        conn._frame_helper.connection_lost(exception)
        raise asyncio.CancelledError

    with (
        patch.object(
            loop,
            "create_connection",
            side_effect=partial(_create_mock_transport_protocol, transport, connected),
        ),
        patch.object(conn, "_connect_hello_login", _mock_frame_helper_error),
    ):
        connect_task = asyncio.create_task(connect(conn, login=False))
        await connected.wait()

    with pytest.raises(raised_exception, match="original message"):
        await connect_task

    assert not conn.is_connected


async def test_connect_resolver_times_out(
    conn: APIConnection, aiohappyeyeballs_start_connection
) -> tuple[APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task]:
    transport = MagicMock()
    connected = asyncio.Event()
    event_loop = asyncio.get_running_loop()

    with (
        patch(
            "aioesphomeapi.host_resolver.async_resolve_host",
            side_effect=ResolveAPIError(
                "Timeout while resolving IP address for fake.address"
            ),
        ),
        patch.object(
            event_loop,
            "create_connection",
            side_effect=partial(_create_mock_transport_protocol, transport, connected),
        ),
        pytest.raises(
            ResolveAPIError,
            match="Timeout while resolving IP address for fake.address",
        ),
    ):
        await connect(conn, login=False)


async def test_disconnect_fails_to_send_response(
    connection_params: ConnectionParams,
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> None:
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    client = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )
    expected_disconnect = None

    async def _on_stop(_expected_disconnect: bool) -> None:
        nonlocal expected_disconnect
        expected_disconnect = _expected_disconnect

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        connect_task = asyncio.create_task(
            connect_client(client, login=False, on_stop=_on_stop)
        )
        await connected.wait()
        protocol = client._connection._frame_helper
        send_plaintext_hello(protocol)
        await connect_task
        transport.reset_mock()

    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)

    await connect_task
    assert client._connection.is_connected

    with patch.object(protocol, "_writelines", side_effect=OSError):
        disconnect_request = DisconnectRequest()
        mock_data_received(protocol, generate_plaintext_packet(disconnect_request))

    # Wait one loop iteration for the disconnect to be processed
    await asyncio.sleep(0)
    assert expected_disconnect is True


async def test_disconnect_success_case(
    connection_params: ConnectionParams,
    resolve_host,
    aiohappyeyeballs_start_connection,
) -> None:
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    client = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )
    expected_disconnect = None

    async def _on_stop(_expected_disconnect: bool) -> None:
        nonlocal expected_disconnect
        expected_disconnect = _expected_disconnect

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        connect_task = asyncio.create_task(
            connect_client(client, login=False, on_stop=_on_stop)
        )
        await connected.wait()
        protocol = client._connection._frame_helper
        send_plaintext_hello(protocol)
        await connect_task
        transport.reset_mock()

    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)

    await connect_task
    assert client._connection.is_connected

    disconnect_request = DisconnectRequest()
    mock_data_received(protocol, generate_plaintext_packet(disconnect_request))

    # Wait one loop iteration for the disconnect to be processed
    await asyncio.sleep(0)
    assert expected_disconnect is True
    assert not client._connection


async def test_ping_disconnects_after_no_responses(
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login

    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)

    await connect_task

    ping_request_bytes = [b"\x00", b"\x00", b"\x07"]

    assert conn.is_connected
    transport.reset_mock()
    expected_calls = []
    start_time = utcnow()
    max_pings_to_disconnect_after = int(KEEP_ALIVE_TIMEOUT_RATIO)
    for count in range(1, max_pings_to_disconnect_after + 1):
        async_fire_time_changed(
            start_time + timedelta(seconds=KEEP_ALIVE_INTERVAL * count)
        )
        assert transport.writelines.call_count == count
        expected_calls.append(call(ping_request_bytes))
        assert transport.writelines.mock_calls == expected_calls

    assert conn.is_connected is True

    # We should disconnect once we reach more than 4 missed pings
    async_fire_time_changed(
        start_time
        + timedelta(seconds=KEEP_ALIVE_INTERVAL * (max_pings_to_disconnect_after + 1))
    )
    assert transport.writelines.call_count == max_pings_to_disconnect_after + 1

    assert conn.is_connected is False


async def test_ping_does_not_disconnect_if_we_get_responses(
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login

    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)

    await connect_task
    ping_request_bytes = [b"\x00", b"\x00", b"\x07"]

    assert conn.is_connected
    transport.reset_mock()
    start_time = utcnow()
    max_pings_to_disconnect_after = int(KEEP_ALIVE_TIMEOUT_RATIO)
    for count in range(1, max_pings_to_disconnect_after + 2):
        async_fire_time_changed(
            start_time + timedelta(seconds=KEEP_ALIVE_INTERVAL * count)
        )
        send_ping_response(protocol)

    # We should only send 1 ping request if we are getting responses
    assert transport.writelines.call_count == 1
    assert transport.writelines.mock_calls == [call(ping_request_bytes)]

    # We should disconnect if we are getting ping responses
    assert conn.is_connected is True


def test_raise_during_send_messages_when_not_yet_connected(conn: APIConnection) -> None:
    """Test that we raise when sending messages before we are connected."""
    with pytest.raises(ConnectionNotEstablishedAPIError):
        conn.send_message(PingRequest())


async def test_respond_to_ping_request(
    caplog: pytest.LogCaptureFixture,
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login

    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)

    await connect_task
    assert conn.is_connected

    transport.reset_mock()
    send_ping_request(protocol)
    # We should respond to ping requests
    ping_response_bytes = [b"\x00", b"\x00", b"\x08"]
    assert transport.writelines.call_count == 1
    assert transport.writelines.mock_calls == [call(ping_response_bytes)]


async def test_unknown_protobuf_message_type_logged(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test unknown protobuf messages are logged but do not cause the connection to collapse."""
    client, connection, transport, protocol = api_client
    response: message.Message = DeviceInfoResponse(
        name="realname",
        friendly_name="My Device",
        has_deep_sleep=True,
    )
    caplog.set_level(logging.DEBUG)
    client.set_debug(True)
    bytes_ = response.SerializeToString()
    message_with_invalid_protobuf_number = (
        b"\0"
        + _cached_varuint_to_bytes(len(bytes_))
        + _cached_varuint_to_bytes(16385)
        + bytes_
    )

    mock_data_received(protocol, message_with_invalid_protobuf_number)

    assert "Skipping unknown message type 16385" in caplog.text
    assert connection.is_connected
    connection.force_disconnect()
    await asyncio.sleep(0)


async def test_bad_protobuf_message_drops_connection(
    api_client: tuple[
        APIClient, APIConnection, asyncio.Transport, APIPlaintextFrameHelper
    ],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test ad bad protobuf messages is logged and causes the connection to collapse."""
    client, connection, transport, protocol = api_client
    msg: message.Message = TextSensorStateResponse(
        key=1, state="invalid", missing_state=False
    )
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    client.set_debug(True)
    bytes_ = msg.SerializeToString()
    # Replace the bytes with invalid UTF-8
    bytes_ = bytes.replace(bytes_, b"invalid", b"inval\xe9 ")

    message_with_bad_protobuf_data = (
        b"\0"
        + _cached_varuint_to_bytes(len(bytes_))
        + _cached_varuint_to_bytes(27)
        + bytes_
    )
    mock_data_received(protocol, message_with_bad_protobuf_data)
    assert "Invalid protobuf message: type=TextSensorStateResponse" in caplog.text
    assert connection.is_connected is False


async def test_connection_cannot_be_reused(
    plaintext_connect_task_with_login: tuple[
        APIConnection, asyncio.Transport, APIPlaintextFrameHelper, asyncio.Task
    ],
) -> None:
    """Test that we raise when trying to connect when already connected."""
    conn, transport, protocol, connect_task = plaintext_connect_task_with_login
    send_plaintext_hello(protocol)
    send_plaintext_connect_response(protocol, False)
    await connect_task
    with pytest.raises(RuntimeError):
        await conn.start_resolve_host()


async def test_attempting_to_finish_unstarted_connection(
    conn: APIConnection,
) -> None:
    """Test that we raise when trying to finish an unstarted connection."""
    with pytest.raises(RuntimeError):
        await conn.finish_connection(login=False)


async def test_start_connection_wrong_state(
    conn: APIConnection,
) -> None:
    """Test that we raise when trying to start connection in wrong state."""
    with pytest.raises(
        RuntimeError,
        match="Connection must be in HOST_RESOLVED state to start connection",
    ):
        await conn.start_connection()


async def test_internal_message_received_immediately_after_connection(
    conn: APIConnection,
    resolve_host: AsyncMock,
    aiohappyeyeballs_start_connection,
) -> None:
    """Test that internal messages received immediately after connection are handled.

    This test verifies the fix for the bug where internal message handlers were
    installed too late. They need to be installed before we init the frame helper
    because as soon as the frame helper is inited we start getting traffic right away.
    If one of those is an internal message we need to process it.
    """
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()

    # Track if ping handler was called
    ping_handled = False

    # Patch the ping handler to track if it's called
    original_ping_handler = conn._handle_ping_request_internal

    def track_ping_handler(*args, **kwargs):
        nonlocal ping_handled
        ping_handled = True
        return original_ping_handler(*args, **kwargs)

    with (
        patch.object(conn, "_handle_ping_request_internal", track_ping_handler),
        patch.object(loop, "create_connection") as create_connection,
    ):
        create_connection.side_effect = partial(
            _create_mock_transport_protocol, transport, connected
        )

        # Start connection
        connect_task = asyncio.create_task(connect(conn, login=False))

        # Wait for connection to establish
        await connected.wait()

        # Simulate receiving a ping request immediately after connection
        # This would happen before the hello/login handshake
        protocol = conn._frame_helper
        assert protocol is not None

        # Create and send a ping request message early
        ping_msg = PingRequest()
        ping_packet = generate_plaintext_packet(ping_msg)
        mock_data_received(protocol, ping_packet)

        # Give async tasks time to process the ping
        await asyncio.sleep(0)

        # Verify the ping handler was called
        assert ping_handled, "Ping handler was not called for early ping message"

        # Now send the expected hello response to let connection complete
        send_plaintext_hello(protocol)
        send_plaintext_connect_response(protocol, False)

        # Wait for the connect task to complete
        await connect_task

        # Clean up
        conn.force_disconnect()
