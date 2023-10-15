import socket
from ipaddress import ip_address

import pytest
from mock import AsyncMock, MagicMock, patch
from zeroconf import DNSCache
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

import aioesphomeapi.host_resolver as hr
from aioesphomeapi.core import APIConnectionError


@pytest.fixture
def async_zeroconf():
    with patch("aioesphomeapi.host_resolver.AsyncZeroconf") as klass:
        async_zeroconf = klass.return_value
        async_zeroconf.async_close = AsyncMock()
        async_zeroconf.zeroconf.cache = DNSCache()
        yield async_zeroconf


@pytest.fixture
def addr_infos():
    return [
        hr.AddrInfo(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            sockaddr=hr.IPv4Sockaddr(address="10.0.0.42", port=6052),
        ),
        hr.AddrInfo(
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            sockaddr=hr.IPv6Sockaddr(
                address="2001:db8:85a3::8a2e:370:7334",
                port=6052,
                flowinfo=0,
                scope_id=0,
            ),
        ),
    ]


@pytest.mark.asyncio
async def test_resolve_host_zeroconf(async_zeroconf: AsyncZeroconf, addr_infos):
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.ip_addresses_by_version.return_value = [
        ip_address(b"\n\x00\x00*"),
        ip_address(b" \x01\r\xb8\x85\xa3\x00\x00\x00\x00\x8a.\x03ps4"),
    ]
    info.async_request = AsyncMock(return_value=True)
    with patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info):
        ret = await hr._async_resolve_host_zeroconf("asdf", 6052)

    info.async_request.assert_called_once()
    async_zeroconf.async_close.assert_called_once_with()
    assert ret == addr_infos


@pytest.mark.asyncio
async def test_resolve_host_passed_zeroconf_does_not_close(addr_infos):
    async_zeroconf = AsyncZeroconf(zc=MagicMock())
    async_zeroconf.async_close = AsyncMock()
    async_zeroconf.zeroconf.cache = DNSCache()
    info = MagicMock(auto_spec=AsyncServiceInfo)
    info.ip_addresses_by_version.return_value = [
        ip_address(b"\n\x00\x00*"),
        ip_address(b" \x01\r\xb8\x85\xa3\x00\x00\x00\x00\x8a.\x03ps4"),
    ]
    info.async_request = AsyncMock(return_value=True)
    with patch("aioesphomeapi.host_resolver.AsyncServiceInfo", return_value=info):
        ret = await hr._async_resolve_host_zeroconf(
            "asdf", 6052, zeroconf_instance=async_zeroconf
        )

    info.async_request.assert_called_once()
    async_zeroconf.async_close.assert_not_called()
    assert ret == addr_infos


@pytest.mark.asyncio
async def test_resolve_host_zeroconf_empty(async_zeroconf: AsyncZeroconf):
    with patch(
        "aioesphomeapi.host_resolver.AsyncServiceInfo.async_request"
    ) as mock_async_request:
        ret = await hr._async_resolve_host_zeroconf("asdf.local", 6052)
    assert mock_async_request.call_count == 1
    assert ret == []


@pytest.mark.asyncio
async def test_resolve_host_getaddrinfo(event_loop, addr_infos):
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


@pytest.mark.asyncio
async def test_resolve_host_getaddrinfo_oserror(event_loop):
    with patch.object(event_loop, "getaddrinfo") as mock:
        mock.side_effect = OSError()
        with pytest.raises(APIConnectionError):
            await hr._async_resolve_host_getaddrinfo("example.com", 6052)


@pytest.mark.asyncio
@patch("aioesphomeapi.host_resolver._async_resolve_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_mdns(resolve_addr, resolve_zc, addr_infos):
    resolve_zc.return_value = addr_infos
    ret = await hr.async_resolve_host("example.local", 6052)

    resolve_zc.assert_called_once_with("example", 6052, zeroconf_instance=None)
    resolve_addr.assert_not_called()
    assert ret == addr_infos[0]


@pytest.mark.asyncio
@patch("aioesphomeapi.host_resolver._async_resolve_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_mdns_empty(resolve_addr, resolve_zc, addr_infos):
    resolve_zc.return_value = []
    resolve_addr.return_value = addr_infos
    ret = await hr.async_resolve_host("example.local", 6052)

    resolve_zc.assert_called_once_with("example", 6052, zeroconf_instance=None)
    resolve_addr.assert_called_once_with("example.local", 6052)
    assert ret == addr_infos[0]


@pytest.mark.asyncio
@patch("aioesphomeapi.host_resolver._async_resolve_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_addrinfo(resolve_addr, resolve_zc, addr_infos):
    resolve_addr.return_value = addr_infos
    ret = await hr.async_resolve_host("example.com", 6052)

    resolve_zc.assert_not_called()
    resolve_addr.assert_called_once_with("example.com", 6052)
    assert ret == addr_infos[0]


@pytest.mark.asyncio
@patch("aioesphomeapi.host_resolver._async_resolve_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_addrinfo_empty(resolve_addr, resolve_zc, addr_infos):
    resolve_addr.return_value = []
    with pytest.raises(APIConnectionError):
        await hr.async_resolve_host("example.com", 6052)

    resolve_zc.assert_not_called()
    resolve_addr.assert_called_once_with("example.com", 6052)


@pytest.mark.asyncio
@patch("aioesphomeapi.host_resolver._async_resolve_host_zeroconf")
@patch("aioesphomeapi.host_resolver._async_resolve_host_getaddrinfo")
async def test_resolve_host_with_address(resolve_addr, resolve_zc):
    resolve_zc.return_value = []
    resolve_addr.return_value = addr_infos
    ret = await hr.async_resolve_host("127.0.0.1", 6052)

    resolve_zc.assert_not_called()
    resolve_addr.assert_not_called()
    assert ret == hr.AddrInfo(
        family=socket.AddressFamily.AF_INET,
        type=socket.SocketKind.SOCK_STREAM,
        proto=6,
        sockaddr=hr.IPv4Sockaddr(address="127.0.0.1", port=6052),
    )
