import asyncio
from unittest.mock import MagicMock, patch

import pytest
from zeroconf import Zeroconf
from zeroconf.asyncio import AsyncZeroconf

from aioesphomeapi import APIConnectionError
from aioesphomeapi.client import APIClient
from aioesphomeapi.reconnect_logic import ReconnectLogic, ReconnectLogicState


def _get_mock_zeroconf() -> MagicMock:
    return MagicMock(spec=Zeroconf)


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
        zeroconf_instance=_get_mock_zeroconf(),
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
        zeroconf_instance=_get_mock_zeroconf(),
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
        zeroconf_instance=_get_mock_zeroconf(),
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
        zeroconf_instance=_get_mock_zeroconf(),
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
        zeroconf_instance=_get_mock_zeroconf(),
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
