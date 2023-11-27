from __future__ import annotations

# Helper script and aioesphomeapi to discover api devices
import asyncio
import logging
import sys

from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

FORMAT = "{: <7}|{: <32}|{: <15}|{: <12}|{: <16}|{: <10}|{: <32}"
COLUMN_NAMES = ("Status", "Name", "Address", "MAC", "Version", "Platform", "Board")


def decode_bytes_or_none(data: str | bytes | None) -> str | None:
    """Decode bytes or return None."""
    if data is None:
        return None
    if isinstance(data, bytes):
        return data.decode()
    return data


def async_service_update(
    zeroconf: Zeroconf,
    service_type: str,
    name: str,
    state_change: ServiceStateChange,
) -> None:
    """Service state changed."""
    short_name = name.partition(".")[0]
    if state_change is ServiceStateChange.Removed:
        state = "OFFLINE"
    else:
        state = "ONLINE"
    info = AsyncServiceInfo(service_type, name)
    info.load_from_cache(zeroconf)
    properties = info.properties
    mac = decode_bytes_or_none(properties.get(b"mac"))
    version = decode_bytes_or_none(properties.get(b"version"))
    platform = decode_bytes_or_none(properties.get(b"platform"))
    board = decode_bytes_or_none(properties.get(b"board"))
    address = ""
    if addresses := info.ip_addresses_by_version(IPVersion.V4Only):
        address = str(addresses[0])

    print(FORMAT.format(state, short_name, address, mac, version, platform, board))


async def main() -> None:
    logging.basicConfig(
        format="%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s",
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    aiozc = AsyncZeroconf()
    browser = AsyncServiceBrowser(
        aiozc.zeroconf, "_esphomelib._tcp.local.", handlers=[async_service_update]
    )
    print(FORMAT.format(*COLUMN_NAMES))
    print("-" * 120)

    try:
        await asyncio.Event().wait()
    finally:
        await browser.async_cancel()
        await aiozc.async_close()


def cli_entry_point() -> None:
    """Run the CLI."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cli_entry_point()
    sys.exit(0)
