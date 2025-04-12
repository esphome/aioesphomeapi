from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Coroutine
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
import itertools
import logging
import socket
from typing import TYPE_CHECKING, Any, cast

from zeroconf import (  # type: ignore[attr-defined]
    BadTypeInNameException,
    DNSPointer,
    IPVersion,
    ServiceStateChange,
    Zeroconf,
    current_time_millis,
)
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from .core import ResolveAPIError, ResolveTimeoutAPIError
from .util import (
    address_is_local,
    asyncio_timeout,
    create_eager_task,
    host_is_name_part,
)
from .zeroconf import ZeroconfManager

_LOGGER = logging.getLogger(__name__)


SERVICE_TYPE = "_esphomelib._tcp.local."
RESOLVE_TIMEOUT = 30.0
CLASS_IN = 1
TYPE_PTR = 12
_TIMEOUT_MS = 3000


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
    aiozc: AsyncZeroconf,
    short_host: str,
    timeout: float,
) -> AsyncServiceInfo:
    info = _make_service_info_for_short_host(short_host)
    try:
        await info.async_request(aiozc.zeroconf, int(timeout * 1000))
    except Exception as exc:
        raise ResolveAPIError(
            f"Error resolving mDNS {short_host} via mDNS: {exc}"
        ) from exc
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
    aiozc: AsyncZeroconf,
    short_host: str,
    port: int,
    *,
    timeout: float = 3.0,
) -> list[AddrInfo]:
    _LOGGER.debug("Resolving host %s via mDNS", short_host)
    service_info = await _async_zeroconf_get_service_info(aiozc, short_host, timeout)
    return service_info_to_addr_info(service_info, port)


def service_info_to_addr_info(info: AsyncServiceInfo, port: int) -> list[AddrInfo]:
    return [
        _async_ip_address_to_addrinfo(ip, port)
        for version in (IPVersion.V6Only, IPVersion.V4Only)
        for ip in info.ip_addresses_by_version(version)
    ]


async def _async_resolve_host_getaddrinfo(host: str, port: int) -> list[AddrInfo]:
    loop = asyncio.get_running_loop()
    try:
        # Limit to TCP IP protocol and SOCK_STREAM
        res = await loop.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError as err:
        raise ResolveAPIError(f"Error resolving {host} to IP address: {err}")

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
    timeout: float = RESOLVE_TIMEOUT,
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
    manager: ZeroconfManager | None = None
    had_zeroconf_instance: bool = False
    resolve_results: defaultdict[str, list[AddrInfo]] = defaultdict(list)
    aiozc: AsyncZeroconf | None = None
    tried_to_create_zeroconf: bool = False
    exceptions: list[BaseException] = []

    # First try to handle the cases where we do not need to
    # do any network calls at all.
    # - If the host is an IP address, we can just return that
    # - If we have a zeroconf manager and the host is in the cache
    #   we can return that as well
    for host in hosts:
        # If its an IP address, we can convert it to an AddrInfo
        # and we are done with this host
        try:
            ip_addr_info = _async_ip_address_to_addrinfo(ip_address(host), port)
        except ValueError:
            pass
        else:
            if ip_addr_info:
                resolve_results[host].append(ip_addr_info)
            continue

        if not host_is_local_name(host):
            continue

        # If its a local name, we can try to fetch it from the zeroconf cache
        if not tried_to_create_zeroconf:
            tried_to_create_zeroconf = True
            manager = zeroconf_manager or ZeroconfManager()
            had_zeroconf_instance = manager.has_instance
            try:
                aiozc = manager.get_async_zeroconf()
            except Exception as original_exc:
                new_exc = ResolveAPIError(
                    f"Cannot start mDNS sockets while resolving {host}: "
                    f"{original_exc}, is this a docker container "
                    "without host network mode? "
                )
                new_exc.__cause__ = original_exc
                exceptions.append(new_exc)

        if aiozc:
            short_host = host.partition(".")[0]
            service_info = _make_service_info_for_short_host(short_host)
            if service_info.load_from_cache(aiozc.zeroconf) and (
                addr_infos := service_info_to_addr_info(service_info, port)
            ):
                resolve_results[host].extend(addr_infos)

    try:
        if len(resolve_results) != len(hosts):
            # If we have not resolved all hosts yet, we need to do some network calls
            try:
                async with asyncio_timeout(timeout):
                    await _async_resolve_host(
                        hosts, port, resolve_results, exceptions, aiozc, timeout
                    )
            except asyncio.TimeoutError as err:
                raise ResolveTimeoutAPIError(
                    f"Timeout while resolving IP address for {hosts}"
                ) from err
    finally:
        if manager and not had_zeroconf_instance:
            await asyncio.shield(create_eager_task(manager.async_close()))

    if addrs := list(itertools.chain.from_iterable(resolve_results.values())):
        return addrs

    if exceptions:
        raise ResolveAPIError(" ,".join([str(exc) for exc in exceptions]))
    raise ResolveAPIError(f"Could not resolve host {hosts} - got no results from OS")


async def _async_resolve_host(
    hosts: list[str],
    port: int,
    resolve_results: defaultdict[str, list[AddrInfo]],
    exceptions: list[BaseException],
    aiozc: AsyncZeroconf | None,
    timeout: float,
) -> None:
    """Resolve hosts in parallel.

    As soon as we get a result for a host, we will cancel
    all other tasks trying to resolve that host.

    This function will resolve hosts in parallel using
    both mDNS and getaddrinfo.

    This function is also designed to be cancellable, so
    if we get cancelled, we will cancel all tasks, and
    clean up after ourselves.
    """
    resolve_task_to_host: dict[asyncio.Task[list[AddrInfo]], str] = {}
    host_tasks: defaultdict[str, set[asyncio.Task[list[AddrInfo]]]] = defaultdict(set)

    try:
        for host in hosts:
            coros: list[Coroutine[Any, Any, list[AddrInfo]]] = []
            if aiozc and host_is_local_name(host):
                short_host = host.partition(".")[0]
                coros.append(
                    _async_resolve_short_host_zeroconf(
                        aiozc, short_host, port, timeout=timeout
                    )
                )

            coros.append(_async_resolve_host_getaddrinfo(host, port))

            for coro in coros:
                task = create_eager_task(coro)
                if task.done():
                    if exc := task.exception():
                        exceptions.append(exc)
                    else:
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
    finally:
        # We likely get here if we get cancelled
        # because of a timeout
        for task in resolve_task_to_host:
            task.cancel()

        # Await all remaining tasks only after cancelling
        # them in case we get cancelled ourselves
        for task in resolve_task_to_host:
            with suppress(asyncio.CancelledError):
                await task


def find_running_browser(azc: AsyncZeroconf) -> AsyncServiceBrowser | None:
    """Find the running browser for the given zeroconf instance."""
    for browser in azc.zeroconf.listeners:
        if not isinstance(browser, AsyncServiceBrowser):
            continue
        if SERVICE_TYPE not in browser.types:
            continue
        return browser

    return None


class ZeroconfRecordWatcher:
    """Watch for a specific zeroconf record."""

    def __init__(
        self, aiozc: AsyncZeroconf, address: IPv4Address | IPv6Address
    ) -> None:
        """Initialize the ZeroconfRecordWatcher."""
        self._aiozc = aiozc
        self._wanted_address = address
        self._resolve_later: dict[str, asyncio.TimerHandle] = {}
        self._stared_browser: bool = False
        self._loop = asyncio.get_running_loop()
        self._background_tasks: set[asyncio.Task[Any]] = set()
        self._running: bool = False
        self._info_future: asyncio.Future[AsyncServiceInfo] = self._loop.create_future()

    async def async_get_info(self) -> AsyncServiceInfo:
        """Get the service info."""
        await self._async_start()
        try:
            async with asyncio_timeout(RESOLVE_TIMEOUT):
                return await self._info_future
        except asyncio.TimeoutError:
            raise ResolveTimeoutAPIError(
                f"Timeout while resolving IP address for {self._wanted_address}"
            )
        finally:
            await self._async_stop()

    async def _async_start(self) -> None:
        """Start the zeroconf browser."""
        self._running = True
        if not (browser := find_running_browser(self._aiozc)):
            browser = AsyncServiceBrowser(
                self._aiozc.zeroconf,
                SERVICE_TYPE,
                handlers=[self._handle_service],
            )
            self._stared_browser = True
            self._browser = browser
            return

        self._browser = browser
        browser.service_state_changed.register_handler(self._handle_service)
        await self._async_update_from_cache(self._aiozc.zeroconf)

    async def _async_update_from_cache(self, zc: Zeroconf) -> None:
        """Load the records from the cache."""
        tasks: list[asyncio.Task[None]] = []
        now = current_time_millis()
        for record in self._async_get_ptr_records(zc):
            try:
                info = AsyncServiceInfo(SERVICE_TYPE, record.alias)
            except BadTypeInNameException as ex:
                _LOGGER.debug(
                    "Ignoring record with bad type in name: %s: %s", record.alias, ex
                )
                continue
            if info.load_from_cache(zc, now):
                self._async_handle_loaded_service_info(info)
            else:
                tasks.append(create_eager_task(self._async_handle_service(info)))

        if tasks:
            await asyncio.gather(*tasks)

    def _async_get_ptr_records(self, zc: Zeroconf) -> list[DNSPointer]:
        return cast(
            list[DNSPointer],
            zc.cache.async_all_by_details(SERVICE_TYPE, TYPE_PTR, CLASS_IN),
        )

    def _handle_service(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if service_type != SERVICE_TYPE:
            return

        if state_change == ServiceStateChange.Removed:
            if cancel := self._resolve_later.pop(name, None):
                cancel.cancel()
            return

        if name in self._resolve_later:
            # We already have a timer to resolve this service, so ignore this
            # callback.
            return

        try:
            info = AsyncServiceInfo(service_type, name)
        except BadTypeInNameException as ex:
            _LOGGER.debug("Ignoring record with bad type in name: %s: %s", name, ex)
            return

        self._resolve_later[name] = self._loop.call_at(
            self._loop.time() + 0.5, self._async_resolve_later, name, info
        )

    def _async_resolve_later(self, name: str, info: AsyncServiceInfo) -> None:
        """Resolve a host later."""
        # As soon as we get a callback, we can remove the _resolve_later
        # so the next time we get a callback, we can resolve the service
        # again if needed which ensures the TTL is respected.
        self._resolve_later.pop(name, None)

        if not self._running:
            return

        if info.load_from_cache(self._aiozc.zeroconf):
            self._async_handle_loaded_service_info(info)
        else:
            task = create_eager_task(self._async_handle_service(info))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

    async def _async_stop(self) -> None:
        self._running = False
        self._browser.service_state_changed.unregister_handler(self._handle_service)
        if self._stared_browser:
            await self._browser.async_cancel()
        for task in self._background_tasks:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        while self._resolve_later:
            _, cancel = self._resolve_later.popitem()
            cancel.cancel()

    async def _async_handle_service(self, info: AsyncServiceInfo) -> None:
        """Add a device that became visible via zeroconf."""
        # AsyncServiceInfo already tries 3x
        if await info.async_request(self._aiozc.zeroconf, _TIMEOUT_MS):
            self._async_handle_loaded_service_info(info)

    def _async_handle_loaded_service_info(self, info: AsyncServiceInfo) -> None:
        """Handle a service info that was discovered via zeroconf."""
        has_wanted_address = False
        for address in info.ip_addresses_by_version(IPVersion.All):
            if address == self._wanted_address:
                has_wanted_address = True
                break

        if not has_wanted_address:
            # This service info does not have the wanted address
            # so we can ignore it.
            return

        if self._info_future.done():
            self._info_future.set_result(info)


async def async_txt_record_for_address(
    address: str | IPv4Address | IPv6Address,
    zeroconf_manager: ZeroconfManager | None = None,
) -> dict[str, str | None] | None:
    """Get the TXT record for a host."""
    ip = ip_address(address)
    manager: ZeroconfManager | None = None
    aiozc: AsyncZeroconf | None = None
    manager = zeroconf_manager or ZeroconfManager()
    had_zeroconf_instance = manager.has_instance
    try:
        aiozc = manager.get_async_zeroconf()
    except Exception as original_exc:
        raise ResolveAPIError(
            f"Cannot start mDNS sockets while resolving {address}: "
            f"{original_exc}, is this a docker container "
            "without host network mode? "
        )
    try:
        return (
            await ZeroconfRecordWatcher(aiozc, ip).async_get_info()
        ).decoded_properties
    finally:
        if not had_zeroconf_instance:
            await asyncio.shield(create_eager_task(manager.async_close()))
