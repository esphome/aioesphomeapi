from __future__ import annotations

import asyncio
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
import itertools
import logging
import socket
from typing import TYPE_CHECKING, cast

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo

from .core import ResolveAPIError
from .util import address_is_local, create_eager_task, host_is_name_part
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
    short_host: str,
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
    info = _make_service_info_for_short_host(short_host)
    try:
        await info.async_request(zc, int(timeout * 1000))
    except Exception as exc:
        raise ResolveAPIError(
            f"Error resolving mDNS {short_host} via mDNS: {exc}"
        ) from exc
    finally:
        if not had_instance:
            await asyncio.shield(create_eager_task(zeroconf_manager.async_close()))
    return info


def _scope_id_to_int(value: str | None) -> int:
    """Convert a scope id to int if possible."""
    if value is None:
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def _make_service_info_for_short_host(host: str) -> AsyncServiceInfo:
    """Make service info for an ESPHome host."""
    service_name = f"{host}.{SERVICE_TYPE}"
    server = f"{host}.local."
    return AsyncServiceInfo(SERVICE_TYPE, service_name, server=server)


async def _async_resolve_short_host_zeroconf(
    short_host: str,
    port: int,
    *,
    timeout: float = 3.0,
    zeroconf_manager: ZeroconfManager | None = None,
) -> list[AddrInfo]:
    _LOGGER.debug("Resolving host %s via mDNS", short_host)
    service_info = await _async_zeroconf_get_service_info(
        zeroconf_manager or ZeroconfManager(),
        short_host,
        timeout,
    )
    return service_info_to_addr_info(service_info, port)


def service_info_to_addr_info(info: AsyncServiceInfo, port: int) -> list[AddrInfo]:
    return [
        _async_ip_address_to_addrinfo(ip, port)
        for version in (IPVersion.V6Only, IPVersion.V4Only)
        for ip in info.ip_addresses_by_version(version)
    ]


async def _async_resolve_host_getaddrinfo(host: str, port: int) -> list[AddrInfo]:
    try:
        # Limit to TCP IP protocol and SOCK_STREAM
        res = await asyncio.get_event_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as err:
        raise ResolveAPIError(f"Error resolving IP address: {err}")

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


def async_addrinfos_from_ips(ips: list[str], port: int) -> list[AddrInfo] | None:
    """Convert a list of IPs to AddrInfos."""
    with suppress(ValueError):
        return [_async_ip_address_to_addrinfo(ip_address(ip), port) for ip in ips]
    # At least one of the IPs is not an IP address
    return None


def async_addrinfos_from_zeroconf_cache(
    zeroconf_manager: ZeroconfManager | None, hosts: list[str], port: int
) -> list[AddrInfo] | None:
    """Convert a list of IPs to AddrInfos."""
    if not zeroconf_manager or not zeroconf_manager.has_instance:
        return None
    aiozc = zeroconf_manager.get_async_zeroconf()
    addrs: list[AddrInfo] = []
    for host in hosts:
        if (
            not host_is_local_name(host)
            or not (short_host := host.partition(".")[0])
            or not (service_info := _make_service_info_for_short_host(short_host))
            or not service_info.load_from_cache(aiozc.zeroconf)
        ):
            # If any host is not in the cache, return None
            # so we can take teh slow path
            return None
        addrs.extend(service_info_to_addr_info(service_info, port))
    return addrs


def _async_ip_address_to_addrinfo(ip: IPv4Address | IPv6Address, port: int) -> AddrInfo:
    """Convert an ipaddress to AddrInfo."""
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

    return AddrInfo(
        family=socket.AF_INET6 if is_ipv6 else socket.AF_INET,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
        sockaddr=sockaddr,
    )


def host_is_local_name(host: str) -> bool:
    """Check if the host is a local name."""
    return host_is_name_part(host) or address_is_local(host)


async def async_resolve_host(
    hosts: list[str],
    port: int,
    zeroconf_manager: ZeroconfManager | None = None,
) -> list[AddrInfo]:
    """Resolve hosts in parallel.

    We will try to resolve the host in the following order:
    - If the host is an IP address, we will return that and skip
      trying to resolve it at all.

    - If the host is a local name, we will try to resolve it via mDNS
    - Otherwise, we will use getaddrinfo to resolve it as well

    Once we know which hosts to resolve and which methods, all
    resolution runs in parallel and we will return the first
    result we get for each host.
    """
    exceptions: list[BaseException] = []
    resolve_task_to_host: dict[asyncio.Task[list[AddrInfo]], str] = {}
    host_tasks: defaultdict[str, set[asyncio.Task[list[AddrInfo]]]] = defaultdict(set)
    resolve_results: defaultdict[str, list[AddrInfo]] = defaultdict(list)

    for host in hosts:
        try:
            resolve_results[host] = [
                _async_ip_address_to_addrinfo(ip_address(host), port)
            ]
        except ValueError:
            pass
        else:
            continue

        tasks: asyncio.Task[list[AddrInfo]] = []
        if host_is_local_name(host) and (short_host := host.partition(".")[0]):
            tasks.append(
                create_eager_task(
                    _async_resolve_short_host_zeroconf(
                        short_host, port, zeroconf_manager=zeroconf_manager
                    )
                )
            )

        tasks.append(create_eager_task(_async_resolve_host_getaddrinfo(host, port)))

        for task in tasks:
            if task.done() and not task.exception():
                resolve_results[host].extend(task.result())
            else:
                resolve_task_to_host[task] = host
                host_tasks[host].add(task)

    while resolve_task_to_host:
        done, _ = await asyncio.wait(
            resolve_task_to_host,
            return_when=asyncio.FIRST_COMPLETED,
        )
        finished_hosts: set[str] = set()
        for task in done:
            host = resolve_task_to_host.pop(task)
            host_tasks[host].discard(task)
            if exc := task.exception():
                exceptions.append(exc)
            elif result := task.result():
                resolve_results[host].extend(result)
                finished_hosts.add(host)

        # We got a result for a host, cancel
        # any other tasks trying to resolve
        # it as we are done with that host
        for host in finished_hosts:
            for task in host_tasks.pop(host, ()):
                resolve_task_to_host.pop(task, None)
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    if addrs := list(itertools.chain.from_iterable(resolve_results.values())):
        return addrs
    if exceptions:
        raise ResolveAPIError(" ,".join([str(exc) for exc in exceptions]))
    raise ResolveAPIError(f"Could not resolve host {hosts} - got no results from OS")
