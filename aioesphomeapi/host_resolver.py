import asyncio
import contextlib
import socket
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import List, Optional, Tuple, Union, cast

import zeroconf
import zeroconf.asyncio

from .core import APIConnectionError, ResolveAPIError

ZeroconfInstanceType = Union[zeroconf.Zeroconf, zeroconf.asyncio.AsyncZeroconf, None]


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
    zeroconf_instance: ZeroconfInstanceType,
    service_type: str,
    service_name: str,
    timeout: float,
) -> Optional["zeroconf.ServiceInfo"]:
    # Use or create zeroconf instance, ensure it's an AsyncZeroconf
    if zeroconf_instance is None:
        try:
            zc = zeroconf.asyncio.AsyncZeroconf()
        except Exception:
            raise ResolveAPIError(
                "Cannot start mDNS sockets, is this a docker container without "
                "host network mode?"
            )
        do_close = True
    elif isinstance(zeroconf_instance, zeroconf.asyncio.AsyncZeroconf):
        zc = zeroconf_instance
        do_close = False
    elif isinstance(zeroconf_instance, zeroconf.Zeroconf):
        zc = zeroconf.asyncio.AsyncZeroconf(zc=zeroconf_instance)
        do_close = False
    else:
        raise ValueError(
            f"Invalid type passed for zeroconf_instance: {type(zeroconf_instance)}"
        )

    try:
        info = await zc.async_get_service_info(
            service_type, service_name, int(timeout * 1000)
        )
    except Exception as exc:
        raise ResolveAPIError(
            f"Error resolving mDNS {service_name} via mDNS: {exc}"
        ) from exc
    finally:
        if do_close:
            await zc.async_close()
    return info


async def _async_resolve_host_zeroconf(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
    zeroconf_instance: ZeroconfInstanceType = None,
) -> List[AddrInfo]:
    service_type = "_esphomelib._tcp.local."
    service_name = f"{host}.{service_type}"

    info = await _async_zeroconf_get_service_info(
        zeroconf_instance, service_type, service_name, timeout
    )

    if info is None:
        return []

    addrs: List[AddrInfo] = []
    for raw in info.addresses_by_version(zeroconf.IPVersion.All):
        is_ipv6 = len(raw) == 16
        sockaddr: Sockaddr
        if is_ipv6:
            sockaddr = IPv6Sockaddr(
                address=socket.inet_ntop(socket.AF_INET6, raw),
                port=port,
                flowinfo=0,
                scope_id=0,
            )
        else:
            sockaddr = IPv4Sockaddr(
                address=socket.inet_ntop(socket.AF_INET, raw),
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


async def _async_resolve_host_getaddrinfo(host: str, port: int) -> List[AddrInfo]:
    try:
        # Limit to TCP IP protocol and SOCK_STREAM
        res = await asyncio.get_event_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as err:
        raise APIConnectionError(f"Error resolving IP address: {err}")

    addrs: List[AddrInfo] = []
    for family, type_, proto, _, raw in res:
        sockaddr: Sockaddr
        if family == socket.AF_INET:
            raw = cast(Tuple[str, int], raw)
            address, port = raw
            sockaddr = IPv4Sockaddr(address=address, port=port)
        elif family == socket.AF_INET6:
            raw = cast(Tuple[str, int, int, int], raw)
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


def _async_ip_address_to_addrs(host: str, port: int) -> List[AddrInfo]:
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
    zeroconf_instance: ZeroconfInstanceType = None,
) -> AddrInfo:
    addrs: List[AddrInfo] = []

    zc_error = None
    if host.endswith(".local"):
        name = host[: -len(".local")]
        try:
            addrs.extend(
                await _async_resolve_host_zeroconf(
                    name, port, zeroconf_instance=zeroconf_instance
                )
            )
        except APIConnectionError as err:
            zc_error = err

    if not addrs:
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
