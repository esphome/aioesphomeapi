import asyncio
import socket
from typing import Optional, Tuple, Any

from aioesphomeapi.core import APIConnectionError


def _varuint_to_bytes(value: int) -> bytes:
    if value <= 0x7F:
        return bytes([value])

    ret = bytes()
    while value:
        temp = value & 0x7F
        value >>= 7
        if value:
            ret += bytes([temp | 0x80])
        else:
            ret += bytes([temp])

    return ret


def _bytes_to_varuint(value: bytes) -> Optional[int]:
    result = 0
    bitpos = 0
    for val in value:
        result |= (val & 0x7F) << bitpos
        bitpos += 7
        if (val & 0x80) == 0:
            return result
    return None


async def resolve_ip_address_getaddrinfo(eventloop: asyncio.events.AbstractEventLoop,
                                         host: str, port: int) -> Tuple[Any, ...]:
    try:
        res = await eventloop.getaddrinfo(host, port, family=socket.AF_INET,
                                          proto=socket.IPPROTO_TCP)
    except OSError as err:
        raise APIConnectionError("Error resolving IP address: {}".format(err))

    if not res:
        raise APIConnectionError("Error resolving IP address: No matches!")

    _, _, _, _, sockaddr = res[0]

    return sockaddr


async def resolve_ip_address(eventloop: asyncio.events.AbstractEventLoop,
                             host: str, port: int) -> Tuple[Any, ...]:
    try:
        return await resolve_ip_address_getaddrinfo(eventloop, host, port)
    except APIConnectionError as err:
        if host.endswith('.local'):
            from aioesphomeapi.host_resolver import resolve_host

            return await eventloop.run_in_executor(None, resolve_host, host), port
        raise err
