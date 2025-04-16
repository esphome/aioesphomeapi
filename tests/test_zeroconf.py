from __future__ import annotations

from unittest.mock import patch

import pytest
from zeroconf.asyncio import AsyncZeroconf

from aioesphomeapi.zeroconf import ZeroconfManager

from .common import get_mock_async_zeroconf


async def test_does_not_closed_passed_in_async_instance(async_zeroconf: AsyncZeroconf):
    """Test that the passed in instance is not closed."""
    manager = ZeroconfManager()
    manager.set_instance(async_zeroconf)
    await manager.async_close()
    assert async_zeroconf.async_close.call_count == 0


async def test_does_not_closed_passed_in_sync_instance(async_zeroconf: AsyncZeroconf):
    """Test that the passed in instance is not closed."""
    manager = ZeroconfManager()
    manager.set_instance(async_zeroconf.zeroconf)
    await manager.async_close()
    assert async_zeroconf.async_close.call_count == 0


async def test_closes_created_instance(async_zeroconf: AsyncZeroconf):
    """Test that the created instance is closed."""
    with patch("aioesphomeapi.zeroconf.AsyncZeroconf", return_value=async_zeroconf):
        manager = ZeroconfManager()
        assert manager.get_async_zeroconf() is async_zeroconf
        await manager.async_close()
    assert async_zeroconf.async_close.call_count == 1


async def test_runtime_error_multiple_instances(async_zeroconf: AsyncZeroconf):
    """Test runtime error is raised on multiple instances."""
    manager = ZeroconfManager(async_zeroconf)
    new_instance = get_mock_async_zeroconf()
    with pytest.raises(RuntimeError):
        manager.set_instance(new_instance)
    manager.set_instance(async_zeroconf)
    manager.set_instance(async_zeroconf.zeroconf)
    manager.set_instance(async_zeroconf)
    await manager.async_close()
    assert async_zeroconf.async_close.call_count == 0
