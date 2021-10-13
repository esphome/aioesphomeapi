import asyncio
import socket

import pytest
from mock import AsyncMock, MagicMock, patch

import aioesphomeapi.host_resolver as hr
from aioesphomeapi.core import APIConnectionError


@pytest.fixture
def async_zeroconf():
    with patch("zeroconf.asyncio.AsyncZeroconf") as klass:
        yield klass.return_value


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
async def test_resolve_host_zeroconf(async_zeroconf, addr_infos):
    info = MagicMock()
    info.addresses_by_version.return_value = [
        b"\n\x00\x00*",
        b" \x01\r\xb8\x85\xa3\x00\x00\x00\x00\x8a.\x03ps4",
    ]
    async_zeroconf.async_get_service_info = AsyncMock(return_value=info)
    async_zeroconf.async_close = AsyncMock()

    ret = await hr._async_resolve_host_zeroconf("asdf", 6052)

    async_zeroconf.async_get_service_info.assert_called_once_with(
        "_esphomelib._tcp.local.", "asdf._esphomelib._tcp.local.", 3000
    )
    async_zeroconf.async_close.assert_called_once_with()

    assert ret == addr_infos


@pytest.mark.asyncio
async def test_resolve_host_zeroconf_empty(async_zeroconf):
    async_zeroconf.async_get_service_info = AsyncMock(return_value=None)
    async_zeroconf.async_close = AsyncMock()

    ret = await hr._async_resolve_host_zeroconf("asdf.local", 6052)
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
