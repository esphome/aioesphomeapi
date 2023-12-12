from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING, cast

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo

from .core import APIConnectionError, ResolveAPIError
from .util import address_is_local, host_is_name_part
from .zeroconf import ZeroconfManager

_LOGGER = logging.getLogger(__name__)


SERVICE_TYPE = "_esphomelib._tcp.local."


@dataclass(frozen=True)
class Sockaddr:
    """Base socket address."""

    address: str
    port: int


@dataclass(frozen=True)
class IPv4Sockaddr(Sockaddr):
    """IPv4 socket address."""


@dataclass(frozen=True)
class IPv6Sockaddr(Sockaddr):
    """IPv6 socket address."""

    flowinfo: int
    scope_id: int


@dataclass(frozen=True)
class AddrInfo:
    family: int
    type: int
    proto: int
    sockaddr: IPv4Sockaddr | IPv6Sockaddr


async def _async_zeroconf_get_service_info(
    zeroconf_manager: ZeroconfManager,
    service_type: str,
    service_name: str,
    server: str,
    timeout: float,
) -> AsyncServiceInfo:
    # Use or create zeroconf instance, ensure it's an AsyncZeroconf
    had_instance = zeroconf_manager.has_instance
    try:
        zc = zeroconf_manager.get_async_zeroconf().zeroconf
    except Exception as exc:
        raise ResolveAPIError(
            f"Cannot start mDNS sockets: {exc}, is this a docker container without "
            "host network mode?"
        ) from exc
    try:
        info = AsyncServiceInfo(service_type, service_name, server=server)
        await info.async_request(zc, int(timeout * 1000))
    except Exception as exc:
        raise ResolveAPIError(
            f"Error resolving mDNS {service_name} via mDNS: {exc}"
        ) from exc
    finally:
        if not had_instance:
            await zeroconf_manager.async_close()
    return info


def _scope_id_to_int(value: str | None) -> int:
    """Convert a scope id to int if possible."""
    if value is None:
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


async def _async_resolve_host_zeroconf(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
    zeroconf_manager: ZeroconfManager | None = None,
) -> list[AddrInfo]:
    service_name = f"{host}.{SERVICE_TYPE}"
    server = f"{host}.local."

    _LOGGER.debug("Resolving host %s via mDNS", service_name)
    info = await _async_zeroconf_get_service_info(
        zeroconf_manager or ZeroconfManager(),
        SERVICE_TYPE,
        service_name,
        server,
        timeout,
    )
    addrs: list[AddrInfo] = []
    for ip in info.ip_addresses_by_version(IPVersion.V6Only):
        addrs.extend(_async_ip_address_to_addrs(ip, port))  # type: ignore
    for ip in info.ip_addresses_by_version(IPVersion.V4Only):
        addrs.extend(_async_ip_address_to_addrs(ip, port))  # type: ignore
    return addrs


async def _async_resolve_host_getaddrinfo(host: str, port: int) -> list[AddrInfo]:
    try:
        # Limit to TCP IP protocol and SOCK_STREAM
        res = await asyncio.get_event_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as err:
        raise APIConnectionError(f"Error resolving IP address: {err}")

    addrs: list[AddrInfo] = []
    for family, type_, proto, _, raw in res:
        sockaddr: IPv4Sockaddr | IPv6Sockaddr
        if family == socket.AF_INET:
            raw = cast(tuple[str, int], raw)
            address, port = raw
            sockaddr = IPv4Sockaddr(address=address, port=port)
        elif family == socket.AF_INET6:
            raw = cast(tuple[str, int, int, int], raw)
            address, port, flowinfo, scope_id = raw
            sockaddr = IPv6Sockaddr(
                address=address, port=port, flowinfo=flowinfo, scope_id=scope_id
            )
        else:
            # Unknown family
            continue

        addrs.append(
            AddrInfo(family=family, type=type_, proto=proto, sockaddr=sockaddr)
        )
    return addrs


def _async_ip_address_to_addrs(
    ip: IPv4Address | IPv6Address, port: int
) -> list[AddrInfo]:
    """Convert an ipaddress to AddrInfo."""
    addrs: list[AddrInfo] = []
    is_ipv6 = ip.version == 6
    sockaddr: IPv6Sockaddr | IPv4Sockaddr
    if is_ipv6:
        if TYPE_CHECKING:
            assert isinstance(ip, IPv6Address)
        sockaddr = IPv6Sockaddr(
            address=str(ip).partition("%")[0],
            port=port,
            flowinfo=0,
            scope_id=_scope_id_to_int(ip.scope_id),
        )
    else:
        sockaddr = IPv4Sockaddr(
            address=str(ip),
            port=port,
        )

    addrs.append(
        AddrInfo(
            family=socket.AF_INET6 if is_ipv6 else socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            sockaddr=sockaddr,
        )
    )
    return addrs


async def async_resolve_host(
    hosts: list[str],
    port: int,
    zeroconf_manager: ZeroconfManager | None = None,
) -> list[AddrInfo]:
    addrs: list[AddrInfo] = []
    zc_error: Exception | None = None

    for host in hosts:
        host_addrs: list[AddrInfo] = []
        host_is_local_name = host_is_name_part(host) or address_is_local(host)

        if host_is_local_name:
            name = host.partition(".")[0]
            try:
                host_addrs.extend(
                    await _async_resolve_host_zeroconf(
                        name, port, zeroconf_manager=zeroconf_manager
                    )
                )
            except ResolveAPIError as err:
                zc_error = err

        if not host_is_local_name:
            try:
                host_addrs.extend(_async_ip_address_to_addrs(ip_address(host), port))
            except ValueError:
                # Not an IP address
                pass

        if not host_addrs:
            host_addrs.extend(await _async_resolve_host_getaddrinfo(host, port))

        addrs.extend(host_addrs)

    if not addrs:
        if zc_error:
            # Only show ZC error if getaddrinfo also didn't work
            raise zc_error
        raise ResolveAPIError(
            f"Could not resolve host {hosts} - got no results from OS"
        )

    return addrs
