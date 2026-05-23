from __future__ import annotations

import argparse

# Helper script and aioesphomeapi to discover api devices
import asyncio
import contextlib
import logging
import re
import sys

from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from ._sanitize import safe_label_str

FORMAT = "{: <7}|{: <32}|{: <15}|{: <12}|{: <16}|{: <10}|{: <32}"
COLUMN_NAMES = ("Status", "Name", "Address", "MAC", "Version", "Platform", "Board")
UNKNOWN = "unknown"

# Per-column display caps for peer-supplied mDNS labels, derived from the
# FORMAT widths so a hostile broadcaster can't widen a column by stuffing a
# long value; deriving them from FORMAT keeps the caps in lock-step if the
# table layout is ever retuned.
_COLUMN_WIDTHS = tuple(int(w) for w in re.findall(r"<\s*(\d+)", FORMAT))
assert len(_COLUMN_WIDTHS) == len(COLUMN_NAMES), (  # noqa: S101  # module-load layout invariant
    "FORMAT width count must match COLUMN_NAMES; update one and the other together"
)
_MAX_NAME_DISPLAY = _COLUMN_WIDTHS[COLUMN_NAMES.index("Name")]
_MAX_MAC_DISPLAY = _COLUMN_WIDTHS[COLUMN_NAMES.index("MAC")]
_MAX_VERSION_DISPLAY = _COLUMN_WIDTHS[COLUMN_NAMES.index("Version")]
_MAX_PLATFORM_DISPLAY = _COLUMN_WIDTHS[COLUMN_NAMES.index("Platform")]
_MAX_BOARD_DISPLAY = _COLUMN_WIDTHS[COLUMN_NAMES.index("Board")]


def decode_mdns_label_or_unknown(
    data: str | bytes | None, limit: int = _MAX_NAME_DISPLAY
) -> str:
    """Decode peer-supplied mDNS bytes, strip non-printables, length-cap."""
    if data is None:
        return UNKNOWN
    if isinstance(data, bytes):
        # A device on the LAN can broadcast arbitrary bytes; use "replace" so
        # a malformed UTF-8 payload doesn't raise out of the zeroconf callback.
        data = data.decode("utf-8", "replace")
    return safe_label_str(data, limit)


def async_service_update(
    zeroconf: Zeroconf,
    service_type: str,
    name: str,
    state_change: ServiceStateChange,
) -> None:
    """Service state changed."""
    # The mDNS service name is peer-controlled — sanitize before printing so
    # a hostile broadcaster can't inject ANSI escapes / newlines / null bytes
    # into the terminal.
    short_name = safe_label_str(name.partition(".")[0], _MAX_NAME_DISPLAY)
    state = "OFFLINE" if state_change is ServiceStateChange.Removed else "ONLINE"
    info = AsyncServiceInfo(service_type, name)
    info.load_from_cache(zeroconf)
    properties = info.properties
    mac = decode_mdns_label_or_unknown(properties.get(b"mac"), _MAX_MAC_DISPLAY)
    version = decode_mdns_label_or_unknown(
        properties.get(b"version"), _MAX_VERSION_DISPLAY
    )
    platform = decode_mdns_label_or_unknown(
        properties.get(b"platform"), _MAX_PLATFORM_DISPLAY
    )
    board = decode_mdns_label_or_unknown(properties.get(b"board"), _MAX_BOARD_DISPLAY)
    address = ""
    if addresses := info.ip_addresses_by_version(IPVersion.V4Only):
        address = str(addresses[0])

    print(FORMAT.format(state, short_name, address, mac, version, platform, board))


async def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser("aioesphomeapi-discover")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv[1:])
    logging.basicConfig(
        format="%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if args.verbose:
        logging.getLogger("zeroconf").setLevel(logging.DEBUG)

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
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main(sys.argv))


if __name__ == "__main__":
    cli_entry_point()
    sys.exit(0)
