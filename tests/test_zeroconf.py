from __future__ import annotations

import socket
from ipaddress import ip_address
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from zeroconf import DNSCache
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

import aioesphomeapi.host_resolver as hr
from aioesphomeapi.core import APIConnectionError
from aioesphomeapi.zeroconf import ZeroconfManager


@pytest.mark.asyncio
async def test_does_not_closed_passed_in_async_instance(async_zeroconf: AsyncZeroconf):
    """Test that the passed in instance is not closed."""
    manager = ZeroconfManager()
    manager.set_instance(async_zeroconf)
    await manager.async_close()
    assert async_zeroconf.async_close.call_count == 0


@pytest.mark.asyncio
async def test_does_not_closed_passed_in_sync_instance(async_zeroconf: AsyncZeroconf):
    """Test that the passed in instance is not closed."""
    manager = ZeroconfManager()
    manager.set_instance(async_zeroconf.zeroconf)
    await manager.async_close()
    assert async_zeroconf.async_close.call_count == 0


@pytest.mark.asyncio
async def test_closes_created_instance(async_zeroconf: AsyncZeroconf):
    """Test that the created instance is closed."""
    with patch("aioesphomeapi.zeroconf.AsyncZeroconf", return_value=async_zeroconf):
        manager = ZeroconfManager()
        assert manager.get_async_zeroconf() is async_zeroconf
        await manager.async_close()
    assert async_zeroconf.async_close.call_count == 1
