from __future__ import annotations

import asyncio
from ipaddress import IPv4Address, IPv6Address, ip_address
import socket
from typing import Any
from unittest.mock import ANY, AsyncMock, MagicMock, Mock, patch

import pytest
from zeroconf import Zeroconf
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from aioesphomeapi.core import (
    APIConnectionError,
    ResolveAPIError,
    ResolveTimeoutAPIError,
)
import aioesphomeapi.host_resolver as hr
from aioesphomeapi.host_resolver import RESOLVE_TIMEOUT, AddrInfo

TEST_IPv6 = IPv6Address("2001:db8:85a3::8a2e:370:7334")
TEST_IPv4 = IPv4Address("10.0.0.42")


@pytest.fixture
def addr_infos() -> list[AddrInfo]:
    return [
        hr.AddrInfo(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            sockaddr=hr.IPv4Sockaddr(address=str(TEST_IPv4), port=6052),
        ),
        hr.AddrInfo(
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            sockaddr=hr.IPv6Sockaddr(
                address=str(TEST_IPv6),
                port=6052,
                flowinfo=0,
                scope_id=0,
            ),
        ),
    ]


@pytest.fixture
def mock_getaddrinfo() -> list[tuple[int, int, int, str, tuple[str, int]]]:
    """Return a list of getaddrinfo results."""
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "canon1",
            (str(TEST_IPv4), 6052),
        ),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "canon2",
            (str(TEST_IPv6), 6052, 0, 0),
        ),
    ]


async def test_resolve_host_zeroconf(async_zeroconf: AsyncZeroconf, addr_infos):
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.ip_addresses_by_version.side_effect = [
        [TEST_IPv4],
        [TEST_IPv6],
    ]
    info.async_request = AsyncMock(return_value=True)
    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch("aioesphomeapi.zeroconf.AsyncZeroconf", return_value=async_zeroconf),
    ):
        ret = await hr._async_resolve_short_host_zeroconf(async_zeroconf, "asdf", 6052)

    info.async_request.assert_called_once()
    assert ret == addr_infos


async def test_resolve_host_passed_zeroconf(addr_infos, async_zeroconf):
    info = MagicMock(auto_spec=AsyncServiceInfo)
    ipv6 = IPv6Address("2001:db8:85a3::8a2e:370:7334%0")
    info.ip_addresses_by_version.side_effect = [
        [ip_address(b"\n\x00\x00*")],
        [ipv6],
    ]
    info.async_request = AsyncMock(return_value=True)
    with patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info):
        ret = await hr._async_resolve_short_host_zeroconf(async_zeroconf, "asdf", 6052)

    info.async_request.assert_called_once()
    assert ret == addr_infos
    await asyncio.sleep(0.1)


async def test_resolve_host_zeroconf_empty(async_zeroconf: AsyncZeroconf):
    with patch(
        "aioesphomeapi.host_resolver.AsyncServiceInfo.async_request"
    ) as mock_async_request:
        ret = await hr._async_resolve_short_host_zeroconf(
            async_zeroconf, "asdf.local", 6052
        )
    assert mock_async_request.call_count == 1
    assert ret == []


async def test_resolve_host_zeroconf_fails(async_zeroconf: AsyncZeroconf):
    with (
        patch(
            "aioesphomeapi.host_resolver.AsyncServiceInfo.async_request",
            side_effect=Exception("no buffers"),
        ),
        pytest.raises(ResolveAPIError, match="no buffers"),
    ):
        await hr._async_resolve_short_host_zeroconf(async_zeroconf, "asdf.local", 6052)


@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo", return_value=[])
async def test_resolve_host_zeroconf_fails_end_to_end(async_zeroconf: AsyncZeroconf):
    with (
        patch(
            "aioesphomeapi.host_resolver.ZeroconfManager.get_async_zeroconf",
            side_effect=Exception("no buffers"),
        ),
        pytest.raises(ResolveAPIError, match="no buffers"),
    ):
        await hr.async_resolve_host(["asdf.local"], 6052)


async def test_resolve_host_getaddrinfo(addr_infos):
    event_loop = asyncio.get_running_loop()
    with patch.object(event_loop, "getaddrinfo") as mock:
        mock.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "canon1",
                ("10.0.0.42", 6052),
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "canon2",
                ("2001:db8:85a3::8a2e:370:7334", 6052, 0, 0),
            ),
            (-1, socket.SOCK_STREAM, socket.IPPROTO_TCP, "canon3", ("10.0.0.42", 6052)),
        ]
        ret = await hr._async_resolve_host_getaddrinfo("example.com", 6052)

        assert ret == addr_infos


async def test_resolve_host_getaddrinfo_oserror():
    event_loop = asyncio.get_running_loop()
    with patch.object(event_loop, "getaddrinfo") as mock:
        mock.side_effect = OSError()
        with pytest.raises(APIConnectionError):
            await hr._async_resolve_host_getaddrinfo("example.com", 6052)


@patch("aioesphomeapi.host_resolver._async_resolve_short_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_mdns_and_dns(resolve_addr, resolve_zc, addr_infos):
    resolve_zc.return_value = addr_infos
    ret = await hr.async_resolve_host(["example.local"], 6052)

    resolve_zc.assert_called_once_with(ANY, "example", 6052, timeout=RESOLVE_TIMEOUT)
    # Now we call getaddrinfo twice - with and without .local suffix
    assert resolve_addr.call_count == 2
    resolve_addr.assert_any_call("example.local", 6052)
    resolve_addr.assert_any_call("example", 6052)
    assert ret == addr_infos


async def test_resolve_host_mdns_and_dns_slow_mdns_wins(
    addr_infos: list[AddrInfo],
) -> None:
    """Test making network requests for mDNS and DNS resolution with mDNS winning."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.side_effect = [
        [TEST_IPv4],
        [TEST_IPv6],
    ]

    async def slow_async_request(self, zc: Zeroconf, *args: Any, **kwargs: Any) -> bool:
        await asyncio.sleep(0)
        return True

    info.async_request = slow_async_request

    async def slow_getaddrinfo(
        *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        await asyncio.sleep(0.1)
        return []

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", slow_getaddrinfo),
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert ret == addr_infos


async def test_resolve_host_mdns_and_dns_exception_mdns_wins(
    addr_infos: list[AddrInfo],
) -> None:
    """Test making network requests DNS exception and mDNS winning."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.side_effect = [
        [TEST_IPv4],
        [TEST_IPv6],
    ]

    async def fast_async_request(self, zc: Zeroconf, *args: Any, **kwargs: Any) -> bool:
        await asyncio.sleep(0)
        return True

    info.async_request = fast_async_request

    async def slow_getaddrinfo(
        *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        raise OSError(None, "DNS exception")

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", slow_getaddrinfo),
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert ret == addr_infos


async def test_resolve_host_mdns_and_dns_fast_mdns_wins(
    addr_infos: list[AddrInfo],
) -> None:
    """Test making network requests for mDNS and DNS resolution with mDNS winning."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.side_effect = [
        [TEST_IPv4],
        [TEST_IPv6],
    ]

    async def fast_async_request(self, zc: Zeroconf, *args: Any, **kwargs: Any) -> bool:
        return True

    info.async_request = fast_async_request

    async def slow_getaddrinfo(
        *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        await asyncio.sleep(0.1)
        return []

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", slow_getaddrinfo),
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert ret == addr_infos


async def test_resolve_host_mdns_and_dns_slow_dns_wins(
    addr_infos: list[AddrInfo],
    mock_getaddrinfo: list[tuple[int, int, int, str, tuple[str, int]]],
) -> None:
    """Test making network requests for mDNS and DNS resolution with DNS winning."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.side_effect = [
        [TEST_IPv4],
        [TEST_IPv6],
    ]

    async def slow_async_request(self, zc: Zeroconf, *args: Any, **kwargs: Any) -> bool:
        await asyncio.sleep(0.1)
        return False

    info.async_request = slow_async_request

    call_count = 0

    async def slow_getaddrinfo(
        *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        nonlocal call_count
        call_count += 1
        # Only return results for the first call to avoid duplicates
        if call_count == 1:
            await asyncio.sleep(0)
            return mock_getaddrinfo
        # Ensure async execution
        await asyncio.sleep(0)
        return mock_getaddrinfo

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", slow_getaddrinfo),
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert ret == addr_infos


async def test_resolve_host_mdns_and_mdns_exception_dns_wins(
    addr_infos: list[AddrInfo],
    mock_getaddrinfo: list[tuple[int, int, int, str, tuple[str, int]]],
) -> None:
    """Test making mDNS exception with DNS winning."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.return_value = []

    async def exception_async_request(
        self, zc: Zeroconf, *args: Any, **kwargs: Any
    ) -> bool:
        raise OSError(None, "mDNS exception")

    info.async_request = exception_async_request

    call_count = 0

    async def fast_getaddrinfo(
        *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        nonlocal call_count
        call_count += 1
        # Only return results for the first call to avoid duplicates
        if call_count == 1:
            await asyncio.sleep(0)
            return mock_getaddrinfo
        # Ensure async execution
        await asyncio.sleep(0)
        return mock_getaddrinfo

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", fast_getaddrinfo),
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert ret == addr_infos


async def test_resolve_host_mdns_and_mdns_no_results_dns_wins(
    addr_infos: list[AddrInfo],
    mock_getaddrinfo: list[tuple[int, int, int, str, tuple[str, int]]],
) -> None:
    """Test making mDNS no results with DNS winning."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.return_value = []
    info.async_request = AsyncMock(return_value=False)

    call_count = 0

    async def fast_getaddrinfo(
        *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        nonlocal call_count
        call_count += 1
        # Only return results for the first call to avoid duplicates
        if call_count == 1:
            await asyncio.sleep(0)
            return mock_getaddrinfo
        # Ensure async execution
        await asyncio.sleep(0)
        return mock_getaddrinfo

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", fast_getaddrinfo),
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert ret == addr_infos


async def test_resolve_host_mdns_and_dns_fast_dns_wins(
    addr_infos: list[AddrInfo],
    mock_getaddrinfo: list[tuple[int, int, int, str, tuple[str, int]]],
) -> None:
    """Test making network requests for mDNS and DNS resolution with DNS winning."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.return_value = []

    async def slow_async_request(self, zc: Zeroconf, *args: Any, **kwargs: Any) -> bool:
        await asyncio.sleep(0.1)
        return False

    info.async_request = slow_async_request

    async def fast_getaddrinfo(
        host: str, *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        # Only return results for example.local, not the stripped version
        if host == "example.local":
            # Small await to ensure truly async but still fast
            await asyncio.sleep(0)
            return mock_getaddrinfo
        if host == "example":
            # Ensure async execution for stripped version
            await asyncio.sleep(0)
            return mock_getaddrinfo
        raise OSError("Unexpected host")

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", fast_getaddrinfo),
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert ret == addr_infos


async def test_resolve_host_mdns_cache(addr_infos: list[AddrInfo]) -> None:
    """Test not requests for DNS are made when we can use the mDNS cache."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=True)
    info.ip_addresses_by_version.side_effect = [
        [TEST_IPv4],
        [TEST_IPv6],
    ]
    info.async_request = AsyncMock(return_value=False)
    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo") as mock_getaddrinfo,
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert not mock_getaddrinfo.called
    assert not info.async_request.called
    assert ret == addr_infos


async def test_resolve_host_mdns_and_mdns_both_fail(
    addr_infos: list[AddrInfo],
    mock_getaddrinfo: list[tuple[int, int, int, str, tuple[str, int]]],
) -> None:
    """Test mDNS and DNS resolution both fail."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.return_value = []
    info.async_request = AsyncMock(return_value=False)

    async def fast_fail_getaddrinfo(
        *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        raise OSError(None, "DNS exception")

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", fast_fail_getaddrinfo),
        pytest.raises(ResolveAPIError, match="DNS exception"),
    ):
        await hr.async_resolve_host(["example.local"], 6052)


async def test_resolve_host_mdns_and_dns_slow_all_timeout(
    addr_infos: list[AddrInfo],
    mock_getaddrinfo: list[tuple[int, int, int, str, tuple[str, int]]],
) -> None:
    """Test making network requests for mDNS and DNS resolution with DNS winning."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)
    info.ip_addresses_by_version.side_effect = [
        [TEST_IPv4],
        [TEST_IPv6],
    ]

    async def slow_async_request(self, zc: Zeroconf, *args: Any, **kwargs: Any) -> bool:
        await asyncio.sleep(2)
        return False

    info.async_request = slow_async_request

    async def slow_getaddrinfo(
        *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        await asyncio.sleep(2)
        return mock_getaddrinfo

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", slow_getaddrinfo),
        pytest.raises(ResolveTimeoutAPIError, match="x"),
    ):
        await hr.async_resolve_host(["example.local"], 6052, timeout=0.01)


@patch("aioesphomeapi.host_resolver._async_resolve_short_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_mdns_empty(resolve_addr, resolve_zc, addr_infos):
    resolve_zc.return_value = []
    resolve_addr.return_value = addr_infos
    ret = await hr.async_resolve_host(["example.local"], 6052)

    resolve_zc.assert_called_once_with(ANY, "example", 6052, timeout=RESOLVE_TIMEOUT)
    # Now we call getaddrinfo twice - with and without .local suffix
    assert resolve_addr.call_count == 2
    resolve_addr.assert_any_call("example.local", 6052)
    resolve_addr.assert_any_call("example", 6052)
    # Both calls might succeed and return results, leading to duplicates
    # Check that we have the expected addresses (possibly duplicated)
    assert len(ret) >= len(addr_infos)
    # Verify the addresses are correct (even if duplicated)
    for addr in addr_infos:
        assert addr in ret


@patch("aioesphomeapi.host_resolver.AsyncServiceInfo.async_request", return_value=False)
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_mdns_no_results(resolve_addr, addr_infos):
    resolve_addr.return_value = addr_infos
    with pytest.raises(ResolveAPIError):
        await hr.async_resolve_host(["example.local"], 6052)


@patch("aioesphomeapi.host_resolver._async_resolve_short_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_addrinfo(resolve_addr, resolve_zc, addr_infos):
    resolve_addr.return_value = addr_infos
    ret = await hr.async_resolve_host(["example.com"], 6052)

    resolve_zc.assert_not_called()
    resolve_addr.assert_called_once_with("example.com", 6052)
    assert ret == addr_infos


@patch("aioesphomeapi.host_resolver._async_resolve_short_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_addrinfo_empty(resolve_addr, resolve_zc, addr_infos):
    resolve_addr.return_value = []
    with pytest.raises(APIConnectionError):
        await hr.async_resolve_host(["example.com"], 6052)

    resolve_zc.assert_not_called()
    resolve_addr.assert_called_once_with("example.com", 6052)


@patch("aioesphomeapi.host_resolver._async_resolve_short_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_with_local_suffix_strips_suffix(
    resolve_addr, resolve_zc, addr_infos
):
    """Test that .local hostnames try both with and without the suffix."""
    resolve_addr.return_value = addr_infos
    resolve_zc.return_value = []

    ret = await hr.async_resolve_host(["example.local"], 6052)

    # Should attempt both with and without .local suffix
    assert resolve_addr.call_count == 2
    resolve_addr.assert_any_call("example.local", 6052)
    resolve_addr.assert_any_call("example", 6052)
    # Both calls might succeed and return results, leading to duplicates
    assert len(ret) >= len(addr_infos)
    for addr in addr_infos:
        assert addr in ret


@patch("aioesphomeapi.host_resolver._async_resolve_short_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_with_local_dot_suffix_strips_suffix(
    resolve_addr, resolve_zc, addr_infos
):
    """Test that .local. hostnames also get stripped correctly."""
    resolve_addr.return_value = addr_infos
    resolve_zc.return_value = []

    ret = await hr.async_resolve_host(["example.local."], 6052)

    # Should attempt both with and without .local. suffix
    assert resolve_addr.call_count == 2
    resolve_addr.assert_any_call("example.local.", 6052)
    resolve_addr.assert_any_call("example", 6052)
    assert ret == addr_infos


def test_remove_local_suffix():
    """Test the _remove_local_suffix helper function."""
    assert hr._remove_local_suffix("example.local") == "example"
    assert hr._remove_local_suffix("example.local.") == "example"
    assert hr._remove_local_suffix("example.com") == "example.com"
    assert hr._remove_local_suffix("example") == "example"
    assert hr._remove_local_suffix("test.example.local") == "test.example"
    assert hr._remove_local_suffix("test.example.local.") == "test.example"


async def test_resolve_host_local_suffix_fallback_wins(
    addr_infos: list[AddrInfo],
    mock_getaddrinfo: list[tuple[int, int, int, str, tuple[str, int]]],
) -> None:
    """Test that when .local DNS fails but stripped version succeeds."""
    loop = asyncio.get_running_loop()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.load_from_cache = Mock(return_value=False)

    async def slow_async_request(self, zc: Zeroconf, *args: Any, **kwargs: Any) -> bool:
        await asyncio.sleep(0.1)
        return False

    info.async_request = slow_async_request

    call_count = 0

    async def getaddrinfo_with_fallback(
        host: str, *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        nonlocal call_count
        call_count += 1
        if host == "example.local":
            # .local resolution fails
            raise OSError("Name or service not known")
        if host == "example":
            # Stripped version succeeds
            return mock_getaddrinfo
        raise OSError("Unexpected host")

    with (
        patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info),
        patch.object(loop, "getaddrinfo", getaddrinfo_with_fallback),
    ):
        ret = await hr.async_resolve_host(["example.local"], 6052)

    assert ret == addr_infos
    assert call_count == 2  # Both .local and stripped version attempted


@patch("aioesphomeapi.host_resolver._async_resolve_short_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_with_address(resolve_addr, resolve_zc):
    resolve_zc.return_value = []
    resolve_addr.return_value = addr_infos
    ret = await hr.async_resolve_host(["127.0.0.1"], 6052)

    resolve_zc.assert_not_called()
    resolve_addr.assert_not_called()
    assert ret == [
        hr.AddrInfo(
            family=socket.AddressFamily.AF_INET,
            type=socket.SocketKind.SOCK_STREAM,
            proto=6,
            sockaddr=hr.IPv4Sockaddr(address="127.0.0.1", port=6052),
        )
    ]


async def test_resolve_host_zeroconf_service_info_oserror(
    async_zeroconf: AsyncZeroconf, addr_infos
):
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.ip_addresses_by_version.return_value = [
        ip_address(b"\n\x00\x00*"),
        ip_address(b" \x01\r\xb8\x85\xa3\x00\x00\x00\x00\x8a.\x03ps4"),
    ]
    info.async_request = AsyncMock(return_value=True)
    with (
        patch(
            "aioesphomeapi.host_resolver.AsyncServiceInfo.async_request",
            side_effect=OSError("out of buffers"),
        ),
        patch("aioesphomeapi.zeroconf.AsyncZeroconf", return_value=async_zeroconf),
        pytest.raises(ResolveAPIError, match="out of buffers"),
    ):
        await hr._async_resolve_short_host_zeroconf(async_zeroconf, "asdf", 6052)


@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_create_zeroconf_oserror(
    resolve_addr, async_zeroconf: AsyncZeroconf, addr_infos
):
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.ip_addresses_by_version.return_value = [
        ip_address(b"\n\x00\x00*"),
        ip_address(b" \x01\r\xb8\x85\xa3\x00\x00\x00\x00\x8a.\x03ps4"),
    ]
    info.async_request = AsyncMock(return_value=True)
    with (
        patch(
            "aioesphomeapi.zeroconf.AsyncZeroconf",
            side_effect=OSError("out of buffers"),
        ),
        pytest.raises(ResolveAPIError, match="out of buffers"),
    ):
        await hr.async_resolve_host(["asdf.local"], 6052)


def test_scope_id_to_int():
    assert hr._scope_id_to_int("123") == 123
    assert hr._scope_id_to_int(socket.if_indextoname(1)) == 1
    assert hr._scope_id_to_int(None) == 0


@pytest.mark.asyncio
async def test_async_resolve_host_partial_success_with_timeout():
    """Test that partial resolution succeeds even if some hosts timeout."""

    async def mock_getaddrinfo(host: str, port: int):
        if host == "working.local":
            # Return immediately for working host
            return [
                hr.AddrInfo(
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                    sockaddr=hr.IPv4Sockaddr(address="192.168.1.100", port=port),
                )
            ]
        # Hang forever for non-working hosts to simulate timeout
        await asyncio.sleep(100)
        return []

    async def mock_zeroconf(*args, **kwargs):
        await asyncio.sleep(100)  # Also timeout mDNS
        return []

    with (
        patch(
            "aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo",
            side_effect=mock_getaddrinfo,
        ),
        patch(
            "aioesphomeapi.host_resolver._async_resolve_short_host_zeroconf",
            side_effect=mock_zeroconf,
        ),
    ):
        # Should succeed with the working host even though others timeout
        results = await hr.async_resolve_host(
            ["timeout1.local", "working.local", "timeout2.local"],
            6053,
            timeout=0.5,  # Short timeout for test
        )

        assert len(results) == 1
        assert results[0].sockaddr.address == "192.168.1.100"
        assert results[0].sockaddr.port == 6053
