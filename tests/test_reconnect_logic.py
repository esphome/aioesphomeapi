from __future__ import annotations

import asyncio
import logging
from ipaddress import ip_address
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from zeroconf import (
    DNSAddress,
    DNSPointer,
    DNSRecord,
    RecordUpdate,
    Zeroconf,
    current_time_millis,
)
from zeroconf.asyncio import AsyncZeroconf
from zeroconf.const import _CLASS_IN, _TYPE_A, _TYPE_PTR

from aioesphomeapi import APIConnectionError
from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.client import APIClient
from aioesphomeapi.connection import APIConnection
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState

from .common import (
    get_mock_async_zeroconf,
    get_mock_zeroconf,
    send_plaintext_connect_response,
    send_plaintext_hello,
)

logging.getLogger("aioesphomeapi").setLevel(logging.DEBUG)


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_host():
    """Test that the name is set correctly from the host."""
    cli = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=MagicMock(spec=AsyncZeroconf),
    )
    assert cli.log_name == "mydevice.local"


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_host_and_set():
    """Test that the name is set correctly from the host."""
    cli = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert cli.log_name == "mydevice.local"


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_address():
    """Test that the name is set correctly from the address."""
    cli = APIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
    )
    assert cli.log_name == "1.2.3.4"


@pytest.mark.asyncio
async def test_reconnect_logic_name_from_name():
    """Test that the name is set correctly from the address."""
    cli = APIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"


@pytest.mark.asyncio
async def test_reconnect_logic_state():
    """Test that reconnect logic state changes."""
    on_disconnect_called = []
    on_connect_called = []
    on_connect_fail_called = []

    class PatchableAPIClient(APIClient):
        pass

    cli = PatchableAPIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        nonlocal on_disconnect_called
        on_disconnect_called.append(expected_disconnect)

    async def on_connect() -> None:
        nonlocal on_connect_called
        on_connect_called.append(True)

    async def on_connect_fail(connect_exception: Exception) -> None:
        nonlocal on_connect_called
        on_connect_fail_called.append(connect_exception)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
        on_connect_error=on_connect_fail,
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"

    with patch.object(cli, "start_connection", side_effect=APIConnectionError):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 1
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    with patch.object(cli, "start_connection"), patch.object(
        cli, "finish_connection", side_effect=APIConnectionError
    ):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 2
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    with patch.object(cli, "start_connection"), patch.object(cli, "finish_connection"):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 1
    assert len(on_connect_fail_called) == 2
    assert rl._connection_state is ReconnectLogicState.READY

    await rl.stop()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_reconnect_retry():
    """Test that reconnect logic retry."""
    on_disconnect_called = []
    on_connect_called = []
    on_connect_fail_called = []

    class PatchableAPIClient(APIClient):
        pass

    cli = PatchableAPIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        nonlocal on_disconnect_called
        on_disconnect_called.append(expected_disconnect)

    async def on_connect() -> None:
        nonlocal on_connect_called
        on_connect_called.append(True)

    async def on_connect_fail(connect_exception: Exception) -> None:
        nonlocal on_connect_called
        on_connect_fail_called.append(connect_exception)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
        on_connect_error=on_connect_fail,
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"

    with patch.object(cli, "start_connection", side_effect=APIConnectionError):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 1
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    with patch.object(cli, "start_connection"), patch.object(cli, "finish_connection"):
        # Should now retry
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 1
    assert len(on_connect_fail_called) == 1
    assert rl._connection_state is ReconnectLogicState.READY

    await rl.stop()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.parametrize(
    ("record", "should_trigger_zeroconf", "log_text"),
    (
        (
            DNSPointer(
                "_esphomelib._tcp.local.",
                _TYPE_PTR,
                _CLASS_IN,
                1000,
                "mydevice._esphomelib._tcp.local.",
            ),
            True,
            "received mDNS record",
        ),
        (
            DNSPointer(
                "_esphomelib._tcp.local.",
                _TYPE_PTR,
                _CLASS_IN,
                1000,
                "wrong_name._esphomelib._tcp.local.",
            ),
            False,
            "",
        ),
        (
            DNSAddress(
                "mydevice.local.",
                _TYPE_A,
                _CLASS_IN,
                1000,
                ip_address("1.2.3.4").packed,
            ),
            True,
            "received mDNS record",
        ),
    ),
)
@pytest.mark.asyncio
async def test_reconnect_zeroconf(
    caplog: pytest.LogCaptureFixture,
    record: DNSRecord,
    should_trigger_zeroconf: bool,
    log_text: str,
) -> None:
    """Test that reconnect logic retry."""

    class PatchableAPIClient(APIClient):
        pass

    cli = PatchableAPIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 1.2.3.4"

    async def slow_connect_fail(*args, **kwargs):
        await asyncio.sleep(10)
        raise APIConnectionError

    async def quick_connect_fail(*args, **kwargs):
        raise APIConnectionError

    with patch.object(
        cli, "start_connection", side_effect=quick_connect_fail
    ) as mock_start_connection:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_connection.call_count == 1

    with patch.object(
        cli, "start_connection", side_effect=slow_connect_fail
    ) as mock_start_connection:
        await asyncio.sleep(0)

        assert mock_start_connection.call_count == 0

        rl.async_update_records(
            mock_zeroconf, current_time_millis(), [RecordUpdate(record, None)]
        )
        await asyncio.sleep(0)
        assert mock_start_connection.call_count == int(should_trigger_zeroconf)
        assert log_text in caplog.text

    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_reconnect_logic_stop_callback():
    """Test that the stop_callback stops the ReconnectLogic."""
    cli = APIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )
    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    await rl.start()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    await asyncio.sleep(0)
    assert rl._connection_state is ReconnectLogicState.CONNECTING
    assert rl._is_stopped is False
    rl.stop_callback()
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_reconnect_logic_stop_callback_waits_for_handshake():
    """Test that the stop_callback waits for a handshake."""

    class PatchableAPIClient(APIClient):
        pass

    cli = PatchableAPIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
    )
    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    async def slow_connect_fail(*args, **kwargs):
        await asyncio.sleep(10)
        raise APIConnectionError

    with patch.object(cli, "start_connection"), patch.object(
        cli, "finish_connection", side_effect=slow_connect_fail
    ):
        await rl.start()
        for _ in range(3):
            await asyncio.sleep(0)

    assert rl._connection_state is ReconnectLogicState.HANDSHAKING
    assert rl._is_stopped is False
    rl.stop_callback()
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._is_stopped is False
    assert rl._connection_state is ReconnectLogicState.HANDSHAKING

    rl._cancel_connect("forced cancel in test")
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.asyncio
async def test_handling_unexpected_disconnect(event_loop: asyncio.AbstractEventLoop):
    """Test the disconnect callback fires with expected_disconnect=False."""
    loop = asyncio.get_event_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()

    cli = PatchableAPIClient(
        address="1.2.3.4",
        port=6052,
        password=None,
        noise_psk=None,
        expected_name="fake",
        zeroconf_instance=async_zeroconf.zeroconf,
    )

    def _create_mock_transport_protocol(create_func, **kwargs):
        nonlocal protocol
        protocol = create_func()
        protocol.connection_made(transport)
        connected.set()
        return transport, protocol

    connected = asyncio.Event()
    on_disconnect_calls = []

    async def on_disconnect(expected_disconnect: bool) -> None:
        on_disconnect_calls.append(expected_disconnect)

    async def on_connect() -> None:
        connected.set()

    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=async_zeroconf,
        name="fake",
    )

    with patch.object(event_loop, "sock_connect"), patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ):
        await logic.start()
        await connected.wait()
        protocol = cli._connection._frame_helper
        send_plaintext_hello(protocol)
        send_plaintext_connect_response(protocol, False)
        await connected.wait()

    assert cli._connection.is_connected is True
    await asyncio.sleep(0)

    with patch.object(event_loop, "sock_connect"), patch.object(
        loop, "create_connection", side_effect=_create_mock_transport_protocol
    ) as mock_create_connection:
        protocol.eof_received()
        # Wait for the task to run
        await asyncio.sleep(0)
        # Ensure we try to reconnect immediately
        # since its an unexpected disconnect
        assert mock_create_connection.call_count == 0

    assert len(on_disconnect_calls) == 1
    assert on_disconnect_calls[0] is False
    await logic.stop()
