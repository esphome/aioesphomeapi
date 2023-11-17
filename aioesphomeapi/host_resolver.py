from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import cast

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo

from .core import APIConnectionError, ResolveAPIError
from .zeroconf import ZeroconfInstanceType, ZeroconfManager

_LOGGER = logging.getLogger(__name__)


SERVICE_TYPE = "_esphomelib._tcp.local."


@dataclass(frozen=True)
class Sockaddr:
    pass


@dataclass(frozen=True)
class IPv4Sockaddr(Sockaddr):
    address: str
    port: int


@dataclass(frozen=True)
class IPv6Sockaddr(Sockaddr):
    address: str
    port: int
    flowinfo: int
    scope_id: int


@dataclass(frozen=True)
class AddrInfo:
    family: int
    type: int
    proto: int
    sockaddr: Sockaddr


async def _async_zeroconf_get_service_info(
    zeroconf_manager: ZeroconfManager,
    service_type: str,
    service_name: str,
    timeout: float,
) -> AsyncServiceInfo | None:
    # Use or create zeroconf instance, ensure it's an AsyncZeroconf
    try:
        async_zc_instance = zeroconf_manager.get_async_zeroconf()
    except Exception as exc:
        raise ResolveAPIError(
            "Cannot start mDNS sockets, is this a docker container without "
            "host network mode?"
        ) from exc
    try:
        info = AsyncServiceInfo(service_type, service_name)
        if await info.async_request(async_zc_instance.zeroconf, int(timeout * 1000)):
            return info
    except Exception as exc:
        raise ResolveAPIError(
            f"Error resolving mDNS {service_name} via mDNS: {exc}"
        ) from exc
    finally:
        await zeroconf_manager.async_close()
    return info


async def _async_resolve_host_zeroconf(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
    zeroconf_manager: ZeroconfManager = None,
) -> list[AddrInfo]:
    service_name = f"{host}.{SERVICE_TYPE}"

    _LOGGER.debug("Resolving host %s via mDNS", service_name)
    info = await _async_zeroconf_get_service_info(
        zeroconf_manager or ZeroconfManager(), SERVICE_TYPE, service_name, timeout
    )

    if info is None:
        return []

    addrs: list[AddrInfo] = []
    for ip_address in info.ip_addresses_by_version(IPVersion.All):
        is_ipv6 = ip_address.version == 6
        sockaddr: Sockaddr
        if is_ipv6:
            sockaddr = IPv6Sockaddr(
                address=str(ip_address),
                port=port,
                flowinfo=0,
                scope_id=0,
            )
        else:
            sockaddr = IPv4Sockaddr(
                address=str(ip_address),
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
        sockaddr: Sockaddr
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


def _async_ip_address_to_addrs(host: str, port: int) -> list[AddrInfo]:
    """Convert an ipaddress to AddrInfo."""
    with contextlib.suppress(ValueError):
        return [
            AddrInfo(
                family=socket.AF_INET6,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
                sockaddr=IPv6Sockaddr(
                    address=str(IPv6Address(host)), port=port, flowinfo=0, scope_id=0
                ),
            )
        ]

    with contextlib.suppress(ValueError):
        return [
            AddrInfo(
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
                sockaddr=IPv4Sockaddr(
                    address=str(IPv4Address(host)),
                    port=port,
                ),
            )
        ]

    return []


async def async_resolve_host(
    host: str,
    port: int,
    zeroconf_manager: ZeroconfManager = None,
) -> AddrInfo:
    addrs: list[AddrInfo] = []

    zc_error = None
    if "." not in host or host.endswith(".local"):
        name = host.partition(".")[0]
        try:
            addrs.extend(
                await _async_resolve_host_zeroconf(
                    name, port, zeroconf_manager=zeroconf_manager
                )
            )
        except APIConnectionError as err:
            zc_error = err

    else:
        addrs.extend(_async_ip_address_to_addrs(host, port))

    if not addrs:
        addrs.extend(await _async_resolve_host_getaddrinfo(host, port))

    if not addrs:
        if zc_error:
            # Only show ZC error if getaddrinfo also didn't work
            raise zc_error
        raise ResolveAPIError(f"Could not resolve host {host} - got no results from OS")

    # Use first matching result
    # Future: return all matches and use first working one
    return addrs[0]
