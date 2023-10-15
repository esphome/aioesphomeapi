from unittest.mock import MagicMock

import pytest
from zeroconf.asyncio import AsyncZeroconf

from aioesphomeapi.client import APIClient
from aioesphomeapi.reconnect_logic import ReconnectLogic


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
        zeroconf_instance=MagicMock(spec=AsyncZeroconf),
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
        zeroconf_instance=MagicMock(spec=AsyncZeroconf),
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
        zeroconf_instance=MagicMock(spec=AsyncZeroconf),
        name="mydevice",
    )
    assert rl._log_name == "mydevice @ 1.2.3.4"
    assert cli._log_name == "mydevice @ 1.2.3.4"
