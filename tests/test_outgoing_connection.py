"""Tests for device-initiated (outgoing) API connections."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aioesphomeapi import APIClient
from aioesphomeapi.api_pb2 import (  # type: ignore[attr-defined]
    DeviceInfoResponse,
    HelloRequest,
)
from aioesphomeapi.connection import (
    CONNECTION_STATE_SOCKET_OPENED,
    APIConnection,
    make_hello_request,
)
from aioesphomeapi.core import APIConnectionError
from aioesphomeapi.model import DeviceInfo
from aioesphomeapi.outgoing_connection import (
    OutgoingConnectionServer,
    _parse_server_hello,
)
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState

from .common import _make_noise_hello_pkt, get_mock_zeroconf

MAC = "aabbccddeeff"


def _server_hello_frame(
    name: bytes = b"test-device", mac: bytes = MAC.encode()
) -> bytes:
    return _make_noise_hello_pkt(b"\x01" + name + b"\x00" + mac + b"\x00")


async def _tcp_pair() -> tuple[socket.socket, socket.socket]:
    """Create a connected localhost TCP socket pair."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.setblocking(False)
    loop = asyncio.get_running_loop()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setblocking(False)
    await loop.sock_connect(client, listener.getsockname())
    server_side, _ = await loop.sock_accept(listener)
    listener.close()
    return client, server_side


def test_parse_server_hello() -> None:
    assert _parse_server_hello(_server_hello_frame()) == ("test-device", MAC)


def test_parse_server_hello_incomplete() -> None:
    frame = _server_hello_frame()
    assert _parse_server_hello(frame[:2]) is None
    assert _parse_server_hello(frame[:10]) is None


@pytest.mark.parametrize(
    "data",
    [
        b"\x00garbage",  # plaintext indicator
        b"\x01\x7f\xff",  # oversized frame length
        b"\x01\x00\x03\x02ab",  # wrong protocol byte
        b"\x01\x00\x02\x01a",  # no null-separated name/mac
        _server_hello_frame(mac=b"nonsense"),  # malformed mac
    ],
)
def test_parse_server_hello_rejects(data: bytes) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - messages vary by case
        _parse_server_hello(data)


async def test_server_dispatches_to_registered_target() -> None:
    server = OutgoingConnectionServer(port=0)
    adopted: list[socket.socket] = []
    dispatched = asyncio.Event()

    async def adopt(sock: socket.socket) -> bool:
        adopted.append(sock)
        dispatched.set()
        return True

    target = MagicMock()
    target.async_adopt_connection = adopt
    # Separators and case are normalized
    unregister = server.register("AA:BB:CC:DD:EE:FF", target)
    await server.start()
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(_server_hello_frame())
        await writer.drain()
        await asyncio.wait_for(dispatched.wait(), timeout=5)
        sock = adopted[0]
        # The hello was only peeked; the adopted socket still holds the bytes
        assert sock.recv(64) == _server_hello_frame()
        sock.close()
        writer.close()
    finally:
        unregister()
        await server.stop()


@pytest.mark.parametrize(
    "sent",
    [
        _server_hello_frame(mac=b"001122334455"),  # unknown MAC
        b"\x00not a noise frame at all",  # garbage
    ],
)
async def test_server_closes_unwanted_connections(sent: bytes) -> None:
    server = OutgoingConnectionServer(port=0)
    server.register(MAC, MagicMock())
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(sent)
        await writer.drain()
        # Closing with unread bytes in the buffer may surface as a reset
        # instead of a clean EOF depending on timing
        with contextlib.suppress(ConnectionResetError):
            assert await asyncio.wait_for(reader.read(), timeout=5) == b""
        writer.close()
    finally:
        await server.stop()


async def test_server_register_duplicate_raises() -> None:
    server = OutgoingConnectionServer(port=0)
    unregister = server.register(MAC, MagicMock())
    with pytest.raises(ValueError, match="already registered"):
        server.register("aa:bb:cc:dd:ee:ff", MagicMock())
    unregister()
    server.register(MAC, MagicMock())


async def test_start_connection_from_socket(conn: APIConnection) -> None:
    client_sock, server_sock = await _tcp_pair()
    try:
        await conn.start_connection_from_socket(server_sock)
        assert conn.connection_state is CONNECTION_STATE_SOCKET_OPENED
        assert conn.connected_address == "127.0.0.1"
        with pytest.raises(RuntimeError, match="not in init state"):
            await conn.start_connection_from_socket(server_sock)
    finally:
        client_sock.close()
        server_sock.close()


def _make_reconnect_logic() -> tuple[APIClient, ReconnectLogic, AsyncMock, AsyncMock]:
    cli = APIClient(address="127.0.0.1", port=6052, password=None)
    on_connect = AsyncMock()
    on_connect_error = AsyncMock()
    rl = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
        on_connect_error=on_connect_error,
    )
    rl._is_stopped = False
    return cli, rl, on_connect, on_connect_error


async def test_adopt_connection_success() -> None:
    cli, rl, on_connect, _ = _make_reconnect_logic()
    client_sock, server_sock = await _tcp_pair()
    with (
        patch.object(cli, "start_connection_from_socket") as start_mock,
        patch.object(cli, "finish_connection"),
    ):
        assert await rl.async_adopt_connection(server_sock) is True
    assert start_mock.await_count == 1
    assert start_mock.await_args.args == (server_sock,)
    on_connect.assert_awaited_once()
    assert rl._connection_state is ReconnectLogicState.READY
    client_sock.close()
    server_sock.close()


async def test_adopt_connection_refused_when_ready() -> None:
    _, rl, on_connect, _ = _make_reconnect_logic()
    rl._connection_state = ReconnectLogicState.READY
    client_sock, server_sock = await _tcp_pair()
    assert await rl.async_adopt_connection(server_sock) is False
    assert server_sock.fileno() == -1  # closed by the refusal
    on_connect.assert_not_awaited()
    client_sock.close()


async def test_adopt_connection_refused_when_stopped() -> None:
    _, rl, _, _ = _make_reconnect_logic()
    rl._is_stopped = True
    client_sock, server_sock = await _tcp_pair()
    assert await rl.async_adopt_connection(server_sock) is False
    assert server_sock.fileno() == -1
    client_sock.close()


async def test_adopt_connection_failure_schedules_retry() -> None:
    cli, rl, on_connect, on_connect_error = _make_reconnect_logic()
    client_sock, server_sock = await _tcp_pair()
    with (
        patch.object(cli, "start_connection_from_socket"),
        patch.object(cli, "finish_connection", side_effect=APIConnectionError("boom")),
    ):
        assert await rl.async_adopt_connection(server_sock) is False
    on_connect.assert_not_awaited()
    on_connect_error.assert_awaited_once()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._connect_timer is not None or rl._connect_task is not None
    rl._cancel_connect("test cleanup")
    client_sock.close()
    server_sock.close()


def test_make_hello_request_flag() -> None:
    flagged = make_hello_request("client", True)
    assert flagged.outgoing_connection_target is True
    round_trip = HelloRequest.FromString(flagged.SerializeToString())
    assert round_trip.outgoing_connection_target is True

    plain = make_hello_request("client", False)
    assert plain.outgoing_connection_target is False
    round_trip = HelloRequest.FromString(plain.SerializeToString())
    assert round_trip.outgoing_connection_target is False


async def test_api_client_outgoing_connection_target_param() -> None:
    cli = APIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        outgoing_connection_target=True,
    )
    assert cli._params.outgoing_connection_target is True
    cli = APIClient(address="127.0.0.1", port=6052, password=None)
    assert cli._params.outgoing_connection_target is False


def test_device_info_outgoing_connection_supported() -> None:
    info = DeviceInfo.from_pb(
        DeviceInfoResponse(api_outgoing_connection_supported=True)
    )
    assert info.api_outgoing_connection_supported is True
    assert DeviceInfo().api_outgoing_connection_supported is False
