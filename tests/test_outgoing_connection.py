"""Tests for device-initiated (outgoing) API connections."""

from __future__ import annotations

import asyncio
import contextlib
import errno
import logging
import socket
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aioesphomeapi import APIClient
from aioesphomeapi.api_pb2 import (  # type: ignore[attr-defined]
    DeviceInfoResponse,
    HelloRequest,
)
from aioesphomeapi.connection import APIConnection, ConnectionState, _make_hello_request
from aioesphomeapi.core import (
    ZERO_NOISE_PSK,
    APIConnectionError,
    InvalidEncryptionKeyAPIError,
)
from aioesphomeapi.model import DeviceInfo
from aioesphomeapi.outgoing_connection import (
    _MAX_INFO_KEYS_LOGGED,
    _MAX_PENDING,
    OutgoingConnectionServer,
    _parse_server_hello,
)
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState

from .common import _make_noise_hello_pkt, get_mock_zeroconf

if TYPE_CHECKING:
    from collections.abc import Callable

MAC = "aabbccddeeff"


def _server_hello_frame(
    name: bytes = b"test-device", mac: bytes = MAC.encode()
) -> bytes:
    return _make_noise_hello_pkt(b"\x01" + name + b"\x00" + mac + b"\x00")


async def _crash_accept_loop(
    caplog: pytest.LogCaptureFixture, open_listener: Callable[[], object]
) -> None:
    """Open the listener while accept(2) fails fatally; wait for the crash."""
    err = OSError(errno.EBADF, "Bad file descriptor")
    with patch.object(type(asyncio.get_running_loop()), "sock_accept", side_effect=err):
        open_listener()
        for _ in range(50):
            if "Unexpected error in" in caplog.text:
                break
            await asyncio.sleep(0)


def _make_target(adopt: object) -> MagicMock:
    """Build a registration target adopting via the given callable."""
    target = MagicMock()
    target.async_adopt_connection = adopt
    return target


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
        _server_hello_frame(mac=b"\r\n\x1b[0mabcdef"),  # 12 bytes but not hex
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

    target = _make_target(adopt)
    # Separators and case are normalized
    unregister = server.register("AA:BB:CC:DD:EE:FF", target)
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
        server.close()


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
        server.close()


async def test_server_register_invalid_mac_raises() -> None:
    server = OutgoingConnectionServer(port=0)
    with pytest.raises(ValueError, match="expected 12 hex digits"):
        server.register("aa:bb:cc:dd:ee", MagicMock())
    with pytest.raises(ValueError, match="expected 12 hex digits"):
        server.register("my-device-name", MagicMock())


async def test_server_register_duplicate_raises() -> None:
    server = OutgoingConnectionServer(port=0)
    unregister = server.register(MAC, MagicMock())
    with pytest.raises(ValueError, match="already registered"):
        server.register("aa:bb:cc:dd:ee:ff", MagicMock())
    unregister()
    server.register(MAC, MagicMock())
    server.close()


async def test_start_connection_from_socket(conn: APIConnection) -> None:
    client_sock, server_sock = await _tcp_pair()
    try:
        conn.start_connection_from_socket(server_sock)
        assert conn.connection_state is ConnectionState.SOCKET_OPENED
        assert conn.connected_address == "127.0.0.1"
        with pytest.raises(RuntimeError, match="not in init state"):
            conn.start_connection_from_socket(server_sock)
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
    assert start_mock.call_count == 1
    assert start_mock.call_args.args == (server_sock,)
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
    # The uncached inner function: the cached wrapper is a C-level name in
    # Cython builds and cannot be imported
    flagged = _make_hello_request("client", True)
    assert flagged.outgoing_connection_target is True
    round_trip = HelloRequest.FromString(flagged.SerializeToString())
    assert round_trip.outgoing_connection_target is True

    plain = _make_hello_request("client", False)
    assert plain.outgoing_connection_target is False
    round_trip = HelloRequest.FromString(plain.SerializeToString())
    assert round_trip.outgoing_connection_target is False


async def test_api_client_outgoing_connection_target_param() -> None:
    cli = APIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        outgoing_connection_target=True,
    )
    assert cli._params.outgoing_connection_target is True
    assert cli.outgoing_connection_target is True
    cli = APIClient(address="127.0.0.1", port=6052, password=None)
    assert cli.outgoing_connection_target is False


@pytest.mark.parametrize("noise_psk", [None, "", ZERO_NOISE_PSK])
async def test_api_client_outgoing_connection_target_needs_real_key(
    noise_psk: str | None,
) -> None:
    """Devices only honor the declaration with a real key; do not send it without one."""
    cli = APIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        noise_psk=noise_psk,
        outgoing_connection_target=True,
    )
    assert cli.outgoing_connection_target is False


async def test_api_client_clear_noise_psk_clears_target_flag() -> None:
    cli = APIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        noise_psk="QRTIErOb/fcE9Ukd/5qA3RGYMn0Y+p06U58SCtOXvPc=",
        outgoing_connection_target=True,
    )
    cli.clear_noise_psk()
    assert cli.outgoing_connection_target is False


def test_device_info_outgoing_connection_supported() -> None:
    info = DeviceInfo.from_pb(
        DeviceInfoResponse(api_outgoing_connection_supported=True)
    )
    assert info.api_outgoing_connection_supported is True
    assert DeviceInfo().api_outgoing_connection_supported is False


async def test_adopt_connection_preempts_unestablished_attempt() -> None:
    """An in-flight attempt with no socket loses to the inbound connection."""
    cli, rl, on_connect, _ = _make_reconnect_logic()
    rl._connection_state = ReconnectLogicState.CONNECTING
    connect_task = asyncio.get_running_loop().create_future()
    task = asyncio.ensure_future(connect_task)
    rl._connect_task = task
    client_sock, server_sock = await _tcp_pair()
    with (
        patch.object(cli, "start_connection_from_socket"),
        patch.object(cli, "finish_connection"),
    ):
        assert await rl.async_adopt_connection(server_sock) is True
    assert task.cancelled()
    on_connect.assert_awaited_once()
    assert rl._connection_state is ReconnectLogicState.READY
    client_sock.close()
    server_sock.close()


async def test_adopt_connection_failure_does_not_pin_backoff() -> None:
    """A failed adoption cannot escalate the backoff past one ordinary try."""
    cli, rl, _, _ = _make_reconnect_logic()
    rl._tries = 2
    client_sock, server_sock = await _tcp_pair()
    with (
        patch.object(cli, "start_connection_from_socket"),
        patch.object(
            cli, "finish_connection", side_effect=InvalidEncryptionKeyAPIError("bad")
        ),
    ):
        assert await rl.async_adopt_connection(server_sock) is False
    # An auth error normally jumps to MAXIMUM_BACKOFF_TRIES; adoption caps it
    assert rl._tries == 3
    rl._cancel_connect("test cleanup")
    client_sock.close()
    server_sock.close()


async def test_adopt_connection_cancelled_mid_handshake() -> None:
    """Cancellation mid-handshake leaves a scheduled retry behind."""
    cli, rl, on_connect, _ = _make_reconnect_logic()
    client_sock, server_sock = await _tcp_pair()
    with (
        patch.object(cli, "start_connection_from_socket"),
        patch.object(cli, "finish_connection", side_effect=asyncio.CancelledError),
        pytest.raises(asyncio.CancelledError),
    ):
        await rl.async_adopt_connection(server_sock)
    on_connect.assert_not_awaited()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    # The state machine must be able to reconnect on its own
    assert rl._connect_timer is not None or rl._connect_task is not None
    rl._cancel_connect("test cleanup")
    client_sock.close()
    server_sock.close()


async def test_server_ipv4_fallback() -> None:
    """Without dual-stack IPv6 the listener binds IPv4."""
    server = OutgoingConnectionServer(port=0)
    with patch(
        "aioesphomeapi.outgoing_connection.socket.has_dualstack_ipv6",
        return_value=False,
    ):
        server.start()
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.close()
    finally:
        server.close()


async def test_server_identification_timeout() -> None:
    """A connection that never sends a hello is closed after the timeout."""
    server = OutgoingConnectionServer(port=0)
    server.register(MAC, MagicMock())
    try:
        with patch(
            "aioesphomeapi.outgoing_connection._IDENTIFY_TIMEOUT",
            0.05,
        ):
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            assert await asyncio.wait_for(reader.read(), timeout=5) == b""
            writer.close()
    finally:
        server.close()


async def test_server_fatal_accept_error_releases_port_and_restarts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A crashed accept loop dies loudly and frees the port for a restart."""
    server = OutgoingConnectionServer(port=0)
    await _crash_accept_loop(caplog, server.start)
    assert "Unexpected error in" in caplog.text
    assert not server.is_listening
    # The same instance rebinds the freed port and accepts connections
    server.start()
    assert server.is_listening
    _, writer = await asyncio.open_connection("127.0.0.1", server.port)
    writer.close()
    server.close()
    assert not server.is_listening


async def test_server_accept_transient_error_retries(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A retryable accept errno is logged and the loop keeps accepting."""
    server = OutgoingConnectionServer(port=0)
    err = OSError(errno.EMFILE, "Too many open files")
    with (
        patch("aioesphomeapi.outgoing_connection._ACCEPT_ERROR_BACKOFF", 0),
        patch.object(type(asyncio.get_running_loop()), "sock_accept", side_effect=err),
    ):
        server.start()
        # Two warnings prove the loop retried rather than dying
        for _ in range(200):
            if caplog.text.count("Error accepting outgoing connection") >= 2:
                break
            await asyncio.sleep(0)
        assert caplog.text.count("Error accepting outgoing connection") >= 2
        assert "Unexpected error in" not in caplog.text
        server.close()


async def test_server_evicts_oldest_unidentified_when_full() -> None:
    """A full admission table evicts the oldest silent connection."""
    server = OutgoingConnectionServer(port=0)
    dispatched = asyncio.Event()

    async def adopt(sock: socket.socket) -> bool:
        sock.close()
        dispatched.set()
        return True

    target = _make_target(adopt)
    server.register(MAC, target)
    try:
        silent = [
            await asyncio.open_connection("127.0.0.1", server.port)
            for _ in range(_MAX_PENDING)
        ]
        await asyncio.sleep(0.05)
        # A real device dial-in evicts the oldest slot and is still adopted
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(_server_hello_frame())
        await writer.drain()
        await asyncio.wait_for(dispatched.wait(), timeout=5)
        reader0, _ = silent[0]
        with contextlib.suppress(ConnectionResetError):
            assert await asyncio.wait_for(reader0.read(), timeout=5) == b""
        writer.close()
        for _, w in silent:
            w.close()
    finally:
        server.close()


async def test_server_single_adoption_in_flight_per_mac() -> None:
    """A second dial-in for a MAC mid-adoption is closed, not queued."""
    server = OutgoingConnectionServer(port=0)
    first_adopting = asyncio.Event()
    release = asyncio.Event()
    adopted: list[socket.socket] = []

    async def adopt(sock: socket.socket) -> bool:
        adopted.append(sock)
        first_adopting.set()
        await release.wait()
        return True

    target = _make_target(adopt)
    server.register(MAC, target)
    try:
        _, writer1 = await asyncio.open_connection("127.0.0.1", server.port)
        writer1.write(_server_hello_frame())
        await writer1.drain()
        await asyncio.wait_for(first_adopting.wait(), timeout=5)
        # Second dial-in for the same MAC while adoption is in flight
        reader2, writer2 = await asyncio.open_connection("127.0.0.1", server.port)
        writer2.write(_server_hello_frame())
        await writer2.drain()
        with contextlib.suppress(ConnectionResetError):
            assert await asyncio.wait_for(reader2.read(), timeout=5) == b""
        release.set()
        await asyncio.sleep(0)
        assert len(adopted) == 1
        adopted[0].close()
        writer1.close()
        writer2.close()
    finally:
        server.close()


async def test_server_start_twice_is_a_no_op() -> None:
    server = OutgoingConnectionServer(port=0)
    server.start()
    port = server.port
    server.start()
    assert server.port == port
    server.close()


async def test_server_close_releases_port_immediately() -> None:
    """close() is synchronous; the port is free when it returns."""
    server = OutgoingConnectionServer(port=0)
    server.register(MAC, MagicMock())
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    await asyncio.sleep(0.05)  # a silent connection sits in _pending
    server.close()
    assert not server.is_listening
    replacement = OutgoingConnectionServer(port=server.port)
    replacement.start()
    replacement.close()
    # The pending connection was closed rather than left to its timeout
    with contextlib.suppress(ConnectionResetError):
        assert await asyncio.wait_for(reader.read(), timeout=5) == b""
    writer.close()
    await asyncio.sleep(0)  # let the cancelled tasks finish


async def test_server_close_before_crash_callback_runs() -> None:
    """close() before the crash's done callback still tears down cleanly."""
    server = OutgoingConnectionServer(port=0)
    err = OSError(errno.EBADF, "Bad file descriptor")
    with patch.object(type(asyncio.get_running_loop()), "sock_accept", side_effect=err):
        server.start()
        server.close()
    assert not server.is_listening


async def test_server_closes_socket_on_unexpected_identify_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unexpected error during identification still closes the socket."""
    server = OutgoingConnectionServer(port=0)
    server.register(MAC, MagicMock())
    try:
        with patch(
            "aioesphomeapi.outgoing_connection._parse_server_hello",
            side_effect=RuntimeError("boom"),
        ):
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            writer.write(_server_hello_frame())
            await writer.drain()
            with contextlib.suppress(ConnectionResetError):
                assert await asyncio.wait_for(reader.read(), timeout=5) == b""
        assert "Unexpected error in" in caplog.text
        writer.close()
    finally:
        server.close()


async def test_server_closes_socket_when_adoption_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An adoption raising unexpectedly still closes the socket."""
    server = OutgoingConnectionServer(port=0)
    target = MagicMock()
    target.async_adopt_connection = AsyncMock(side_effect=RuntimeError("boom"))
    server.register(MAC, target)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(_server_hello_frame())
        await writer.drain()
        with contextlib.suppress(ConnectionResetError):
            assert await asyncio.wait_for(reader.read(), timeout=5) == b""
        assert "Unexpected error in" in caplog.text
        assert MAC not in server._adopting
        writer.close()
    finally:
        server.close()


async def test_server_logs_not_adopted(caplog: pytest.LogCaptureFixture) -> None:
    """A refused adoption is reported at INFO."""
    server = OutgoingConnectionServer(port=0)
    refused = asyncio.Event()

    async def adopt(sock: socket.socket) -> bool:
        sock.close()
        refused.set()
        return False

    target = _make_target(adopt)
    server.register(MAC, target)
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(_server_hello_frame())
        await writer.drain()
        await asyncio.wait_for(refused.wait(), timeout=5)
        for _ in range(50):
            if "was not adopted" in caplog.text:
                break
            await asyncio.sleep(0)
        assert "was not adopted" in caplog.text
        writer.close()
    finally:
        server.close()


async def test_server_peek_falls_back_without_add_reader() -> None:
    """A proactor loop without add_reader falls back to sleep-polling."""
    server = OutgoingConnectionServer(port=0)
    dispatched = asyncio.Event()

    async def adopt(sock: socket.socket) -> bool:
        sock.close()
        dispatched.set()
        return True

    target = _make_target(adopt)
    server.register(MAC, target)
    try:
        with patch.object(
            type(asyncio.get_running_loop()),
            "add_reader",
            side_effect=NotImplementedError,
        ):
            _, writer = await asyncio.open_connection("127.0.0.1", server.port)
            await asyncio.sleep(0.02)  # let the first peek find no bytes
            writer.write(_server_hello_frame())
            await writer.drain()
            await asyncio.wait_for(dispatched.wait(), timeout=5)
        writer.close()
    finally:
        server.close()


async def test_server_rejects_connection_closed_before_hello(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioesphomeapi.outgoing_connection")
    server = OutgoingConnectionServer(port=0)
    server.register(MAC, MagicMock())
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.close()
        for _ in range(100):
            if "closed before hello" in caplog.text:
                break
            await asyncio.sleep(0.01)
        assert "closed before hello" in caplog.text
    finally:
        server.close()


async def test_server_waits_for_partial_hello() -> None:
    """A hello split across writes is peeked until complete."""
    server = OutgoingConnectionServer(port=0)
    dispatched = asyncio.Event()

    async def adopt(sock: socket.socket) -> bool:
        sock.close()
        dispatched.set()
        return True

    target = _make_target(adopt)
    server.register(MAC, target)
    try:
        frame = _server_hello_frame()
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(frame[:5])
        await writer.drain()
        await asyncio.sleep(0.1)  # a peek must see the partial frame
        writer.write(frame[5:])
        await writer.drain()
        await asyncio.wait_for(dispatched.wait(), timeout=5)
        writer.close()
    finally:
        server.close()


async def test_adopt_connection_refused_after_lock_wait() -> None:
    """A stop that lands while waiting for the lock refuses the adoption."""
    _, rl, on_connect, _ = _make_reconnect_logic()
    client_sock, server_sock = await _tcp_pair()
    await rl._connected_lock.acquire()
    task = asyncio.create_task(rl.async_adopt_connection(server_sock))
    await asyncio.sleep(0)  # adoption passes the pre-check, waits on the lock
    rl._is_stopped = True
    rl._connected_lock.release()
    assert await task is False
    assert server_sock.fileno() == -1
    on_connect.assert_not_awaited()
    client_sock.close()


async def test_adopt_connection_start_failure_schedules_retry() -> None:
    """A failure inside start_connection_from_socket routes to the retry path."""
    cli, rl, on_connect, on_connect_error = _make_reconnect_logic()
    client_sock, server_sock = await _tcp_pair()
    with patch.object(
        cli,
        "start_connection_from_socket",
        side_effect=APIConnectionError("refused"),
    ):
        assert await rl.async_adopt_connection(server_sock) is False
    on_connect.assert_not_awaited()
    on_connect_error.assert_awaited_once()
    client_sock.close()
    server_sock.close()


async def test_client_start_connection_from_socket() -> None:
    cli = APIClient(address="127.0.0.1", port=6052, password=None)
    client_sock, server_sock = await _tcp_pair()
    cli.start_connection_from_socket(server_sock)
    assert cli._connection is not None
    assert cli._connection.connection_state is ConnectionState.SOCKET_OPENED
    cli._connection.force_disconnect()
    client_sock.close()


async def test_client_start_connection_from_socket_closes_on_refusal() -> None:
    """The client owns the socket even when it cannot take the connection."""
    cli = APIClient(address="127.0.0.1", port=6052, password=None)
    client_sock, server_sock = await _tcp_pair()
    with (
        patch.object(cli, "_create_connection", side_effect=APIConnectionError("busy")),
        pytest.raises(APIConnectionError),
    ):
        cli.start_connection_from_socket(server_sock)
    assert server_sock.fileno() == -1
    client_sock.close()


async def test_start_connection_from_socket_bad_socket(conn: APIConnection) -> None:
    """A dead socket surfaces as a connection error, not a raw OSError."""
    client_sock, server_sock = await _tcp_pair()
    server_sock.close()
    with pytest.raises(APIConnectionError):
        conn.start_connection_from_socket(server_sock)
    client_sock.close()


async def test_server_info_log_window_resets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The INFO-once cap clears each window so later issues still surface."""
    caplog.set_level(logging.INFO, logger="aioesphomeapi.outgoing_connection")
    server = OutgoingConnectionServer(port=0)
    with patch("aioesphomeapi.outgoing_connection._INFO_LOG_WINDOW", 0):
        server._log_rate_limited("mac:" + MAC, "unknown %s", MAC)
        server._log_rate_limited("mac:" + MAC, "unknown %s", MAC)
    infos = [
        record
        for record in caplog.records
        if record.levelno == logging.INFO and MAC in record.message
    ]
    # The zero-length window reset between the calls, so both logged at INFO
    assert len(infos) == 2


async def test_server_register_manages_listener_lifecycle() -> None:
    """The first registration opens the listener; the last removal closes it."""
    server = OutgoingConnectionServer(port=0)
    unregister1 = server.register(MAC, MagicMock())
    assert server.is_listening
    port = server.port
    unregister2 = server.register("00:11:22:33:44:55", MagicMock())
    unregister1()
    assert server.is_listening
    unregister2()
    assert not server.is_listening
    # The port was freed synchronously
    replacement = OutgoingConnectionServer(port=port, host="127.0.0.1")
    replacement.start()
    replacement.close()
    # Stale unregister callables cannot close a listener with live routes
    server.register(MAC, MagicMock())
    unregister1()
    unregister2()
    assert server.is_listening
    server.close()
    await asyncio.sleep(0)  # let the cancelled accept tasks finish


async def test_server_register_restarts_dead_listener(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A registration after a fatal accept error brings the listener back."""
    server = OutgoingConnectionServer(port=0)
    await _crash_accept_loop(caplog, lambda: server.register(MAC, MagicMock()))
    assert not server.is_listening
    server.register("00:11:22:33:44:55", MagicMock())
    assert server.is_listening
    _, writer = await asyncio.open_connection("127.0.0.1", server.port)
    writer.close()
    server.close()


async def test_server_register_bind_failure_warns_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A bind failure keeps the route, warns once, and retries on register."""
    caplog.set_level(logging.INFO, logger="aioesphomeapi.outgoing_connection")
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    server = OutgoingConnectionServer(port=port, host="127.0.0.1")
    server.register(MAC, MagicMock())
    assert not server.is_listening
    server.register("00:11:22:33:44:55", MagicMock())
    bind_logs = [
        record for record in caplog.records if "Cannot listen" in record.message
    ]
    # First failure warned, the second reported at info within the window
    assert [record.levelno for record in bind_logs] == [logging.WARNING, logging.INFO]
    blocker.close()
    server.register("00:11:22:33:44:66", MagicMock())
    assert server.is_listening
    assert "after an earlier failure" in caplog.text
    server.close()


async def test_server_bind_warning_window_resets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An expired warning window re-warns instead of staying at info."""
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    server = OutgoingConnectionServer(port=port, host="127.0.0.1")
    with patch("aioesphomeapi.outgoing_connection._BIND_WARN_INTERVAL", 0):
        server.register(MAC, MagicMock())
        server.register("00:11:22:33:44:55", MagicMock())
    blocker.close()
    bind_warnings = [
        record
        for record in caplog.records
        if record.levelno == logging.WARNING and "Cannot listen" in record.message
    ]
    assert len(bind_warnings) == 2
    server.close()


async def test_client_start_connection_from_socket_resets_on_error() -> None:
    """A failing socket setup clears the client's connection reference."""
    cli = APIClient(address="127.0.0.1", port=6052, password=None)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.close()
    with pytest.raises(APIConnectionError):
        cli.start_connection_from_socket(sock)
    assert cli._connection is None


async def test_server_bind_retry_timer() -> None:
    """A bind failure arms a retry timer that rebinds once the port frees."""
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    server = OutgoingConnectionServer(port=port, host="127.0.0.1")
    server.register(MAC, MagicMock())
    assert not server.is_listening
    assert server._bind_retry_handle is not None
    blocker.close()
    server._retry_bind()
    assert server.is_listening
    server.close()
    assert server._bind_retry_handle is None


async def test_server_close_cancels_bind_retry() -> None:
    """Closing while a bind retry is pending cancels the timer."""
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    server = OutgoingConnectionServer(port=blocker.getsockname()[1], host="127.0.0.1")
    unregister = server.register(MAC, MagicMock())
    assert server._bind_retry_handle is not None
    unregister()
    assert server._bind_retry_handle is None
    blocker.close()


async def test_adopt_connection_cancelled_waiting_for_lock() -> None:
    """Cancellation while waiting for the lock reschedules the reconnect."""
    _, rl, _, _ = _make_reconnect_logic()
    client_sock, server_sock = await _tcp_pair()
    async with rl._connected_lock:
        task = asyncio.ensure_future(rl.async_adopt_connection(server_sock))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._connect_timer is not None
    rl._cancel_connect("test cleanup")
    client_sock.close()
    server_sock.close()


async def test_server_info_budget_is_per_class(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Scan noise in one key class cannot demote another class to DEBUG."""
    caplog.set_level(logging.INFO, logger="aioesphomeapi.outgoing_connection")
    server = OutgoingConnectionServer(port=0)
    for i in range(_MAX_INFO_KEYS_LOGGED + 5):
        server._log_rate_limited(f"evict:10.0.0.{i}", "evict %s", i)
    server._log_rate_limited("reject:10.0.0.1", "real failure %s", MAC)
    infos = [
        record
        for record in caplog.records
        if record.levelno == logging.INFO and "real failure" in record.message
    ]
    assert len(infos) == 1


async def test_start_connection_from_socket_strips_v4_mapped(
    conn: APIConnection,
) -> None:
    """A dual-stack listener's ::ffff:-mapped peer is recorded as plain IPv4."""

    class MappedPeerSocket(socket.socket):
        def getpeername(self) -> tuple[str, int]:
            return ("::ffff:127.0.0.1", 6054)

    client_sock, server_sock = await _tcp_pair()
    mapped = MappedPeerSocket(fileno=server_sock.detach())
    try:
        conn.start_connection_from_socket(mapped)
        assert conn.connected_address == "127.0.0.1"
    finally:
        client_sock.close()
        mapped.close()


async def test_adopt_connection_cancelled_after_ready_disconnects() -> None:
    """A cancel after the session reached READY drops the live client."""
    cli, rl, _, _ = _make_reconnect_logic()
    client_sock, server_sock = await _tcp_pair()

    async def on_connect() -> None:
        # The session is READY here; cancelling now must not strand a live
        # client
        raise asyncio.CancelledError

    rl._on_connect_cb = on_connect
    with (
        patch.object(cli, "start_connection_from_socket"),
        patch.object(cli, "finish_connection"),
        patch.object(cli, "force_disconnect") as force_disconnect,
        pytest.raises(asyncio.CancelledError),
    ):
        await rl.async_adopt_connection(server_sock)
    force_disconnect.assert_called_once()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    rl._cancel_connect("test cleanup")
    client_sock.close()
    server_sock.close()


async def test_server_close_unregisters_pending_reader() -> None:
    """close() removes a pending peek's reader before closing its fd."""
    server = OutgoingConnectionServer(port=0)
    server.register(MAC, MagicMock())
    server.start()
    try:
        # A connection that never sends its hello sits in the peek loop
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        for _ in range(50):
            if server._pending:
                break
            await asyncio.sleep(0)
        assert server._pending
        loop = asyncio.get_running_loop()
        with patch.object(loop, "remove_reader", wraps=loop.remove_reader) as removed:
            server.close()
        removed.assert_called()
        writer.close()
    finally:
        server.close()
    await asyncio.sleep(0)


async def test_client_force_disconnect(conn: APIConnection) -> None:
    """force_disconnect drops a live connection and no-ops without one."""
    cli = APIClient(address="127.0.0.1", port=6052, password=None)
    cli.force_disconnect()  # no connection: no error
    cli._connection = conn
    with patch.object(conn, "force_disconnect") as force_disconnect:
        cli.force_disconnect()
    force_disconnect.assert_called_once()


async def test_server_fatal_accept_error_arms_retry(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A listener that dies with routes registered rebinds on the timer."""
    server = OutgoingConnectionServer(port=0)
    await _crash_accept_loop(caplog, lambda: server.register(MAC, MagicMock()))
    assert not server.is_listening
    assert server._bind_retry_handle is not None
    server._retry_bind()
    assert server.is_listening
    server.close()
    assert server._bind_retry_handle is None


async def test_server_fatal_accept_error_without_routes_does_not_retry(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """With nothing registered a dead listener stays down until start()."""
    server = OutgoingConnectionServer(port=0)
    await _crash_accept_loop(caplog, server.start)
    assert not server.is_listening
    assert server._bind_retry_handle is None


async def test_server_close_tolerates_closed_pending_socket() -> None:
    """A pending entry whose identify task already closed its socket is skipped."""
    server = OutgoingConnectionServer(port=0)
    closed = socket.socket()
    closed.close()

    async def noop() -> None:
        pass

    task = asyncio.get_running_loop().create_task(noop())
    await task
    server._pending[task] = closed
    server.close()  # remove_reader(-1) would raise ValueError
    assert not server._pending


async def test_server_closes_accepted_socket_when_setup_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failure between accept and _pending closes the socket."""
    server = OutgoingConnectionServer(port=0)
    server.start()
    client = socket.create_connection(("127.0.0.1", server.port))
    client.settimeout(5)
    loop = asyncio.get_running_loop()
    try:
        with patch.object(loop, "create_task", side_effect=RuntimeError("boom")):
            for _ in range(50):
                if "Unexpected error in" in caplog.text:
                    break
                await asyncio.sleep(0)
        assert "Unexpected error in" in caplog.text
        assert client.recv(1) == b""  # closed by the accept loop, not leaked
    finally:
        client.close()
        server.close()
