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
from aioesphomeapi.client import APIClient
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState

from .common import get_mock_zeroconf

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

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=MagicMock(spec=AsyncZeroconf),
    )
    assert rl._log_name == "mydevice"
    assert cli._log_name == "mydevice"


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

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl._log_name == "mydevice"
    assert cli._log_name == "mydevice"


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

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
    )
    assert rl._log_name == "1.2.3.4"
    assert cli._log_name == "1.2.3.4"


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

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl._log_name == "mydevice @ 1.2.3.4"
    assert cli._log_name == "mydevice @ 1.2.3.4"


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
    assert rl._log_name == "mydevice @ 1.2.3.4"
    assert cli._log_name == "mydevice @ 1.2.3.4"

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
    assert rl._log_name == "mydevice @ 1.2.3.4"
    assert cli._log_name == "mydevice @ 1.2.3.4"

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
    assert rl._log_name == "mydevice @ 1.2.3.4"
    assert cli._log_name == "mydevice @ 1.2.3.4"

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
