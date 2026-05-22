"""Tests for the aioesphomeapi-discover CLI."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, NamedTuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from zeroconf import ServiceStateChange

from aioesphomeapi.discover import (
    _MAX_BOARD_DISPLAY,
    _MAX_MAC_DISPLAY,
    _MAX_NAME_DISPLAY,
    _MAX_PLATFORM_DISPLAY,
    _MAX_VERSION_DISPLAY,
    COLUMN_NAMES,
    FORMAT,
    UNKNOWN,
    async_service_update,
    cli_entry_point,
    decode_mdns_label_or_unknown,
    main,
)

from .common import get_mock_async_zeroconf

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from zeroconf.asyncio import AsyncZeroconf


def test_decode_mdns_label_or_unknown_none() -> None:
    assert decode_mdns_label_or_unknown(None) == UNKNOWN


def test_decode_mdns_label_or_unknown_str_passthrough() -> None:
    assert decode_mdns_label_or_unknown("esp32-board") == "esp32-board"


def test_decode_mdns_label_or_unknown_bytes_utf8() -> None:
    assert decode_mdns_label_or_unknown(b"esp32-board") == "esp32-board"


def test_decode_mdns_label_or_unknown_invalid_utf8_replaces() -> None:
    # Hostile mDNS broadcaster sends non-UTF-8 bytes; result is the U+FFFD
    # replacement character (one per invalid byte), never raises
    # UnicodeDecodeError. Pinning the actual output, not just the type, keeps
    # a future refactor from silently switching to UNKNOWN or empty string.
    assert decode_mdns_label_or_unknown(b"\xff\xfe") == "\ufffd\ufffd"


def test_decode_mdns_label_or_unknown_strips_control_chars() -> None:
    # Strip the ESC byte that activates ANSI sequences, plus newline / CR /
    # null / tab / etc. The trailing "[2J" is harmless printable text once
    # the leading ESC is gone, so a hostile broadcaster can no longer clear
    # the user's terminal from a discovery scan.
    assert decode_mdns_label_or_unknown(b"\x1b[2Jvers\n1.0") == "[2Jvers1.0"
    assert decode_mdns_label_or_unknown(b"line1\r\nline2") == "line1line2"
    assert decode_mdns_label_or_unknown(b"col\tumn") == "column"


def test_decode_mdns_label_or_unknown_strips_null_byte() -> None:
    assert decode_mdns_label_or_unknown(b"esp\x0032") == "esp32"


def test_decode_mdns_label_or_unknown_caps_length() -> None:
    assert decode_mdns_label_or_unknown(b"x" * 200, limit=10) == "x" * 10


def test_decode_mdns_label_or_unknown_default_limit_caps_long_str() -> None:
    # Default cap is the Name column width from FORMAT.
    assert len(decode_mdns_label_or_unknown("a" * 100)) == _MAX_NAME_DISPLAY


def test_decode_mdns_label_or_unknown_unicode_printable_survives() -> None:
    # safe_label_str uses str.isprintable so non-ASCII printable chars stay.
    assert decode_mdns_label_or_unknown("café") == "café"


def test_per_column_caps_match_format_widths() -> None:
    # The per-column caps must equal the FORMAT widths so a peer-controlled
    # value can never widen a column past its slot. If FORMAT changes and
    # this assertion fires, update the cap derivation in discover.py — do
    # not just bump the expected values.
    widths = tuple(int(w) for w in re.findall(r"<\s*(\d+)", FORMAT))
    assert widths[COLUMN_NAMES.index("Name")] == _MAX_NAME_DISPLAY
    assert widths[COLUMN_NAMES.index("MAC")] == _MAX_MAC_DISPLAY
    assert widths[COLUMN_NAMES.index("Version")] == _MAX_VERSION_DISPLAY
    assert widths[COLUMN_NAMES.index("Platform")] == _MAX_PLATFORM_DISPLAY
    assert widths[COLUMN_NAMES.index("Board")] == _MAX_BOARD_DISPLAY


# ---------------------------------------------------------------------------
# async_service_update callback
# ---------------------------------------------------------------------------


class ServiceUpdateResult(NamedTuple):
    """Result of driving async_service_update once via the fixture."""

    info: MagicMock
    zeroconf: MagicMock


@pytest.fixture
def service_update_runner() -> Callable[..., ServiceUpdateResult]:
    """Drive async_service_update once with a fake AsyncServiceInfo patched in."""

    def runner(
        *,
        name: str = "esp32._esphomelib._tcp.local.",
        state_change: ServiceStateChange = ServiceStateChange.Added,
        properties: dict[bytes, bytes] | None = None,
        ipv4: list[str] | None = None,
    ) -> ServiceUpdateResult:
        info = MagicMock()
        info.properties = properties or {}
        # The CLI passes addresses[0] through str(); plain strings round-trip
        # fine and avoid MagicMock's special __str__ handling.
        info.ip_addresses_by_version.return_value = list(ipv4 or [])
        zeroconf = MagicMock()
        with patch("aioesphomeapi.discover.AsyncServiceInfo", return_value=info):
            async_service_update(
                zeroconf, "_esphomelib._tcp.local.", name, state_change
            )
        return ServiceUpdateResult(info=info, zeroconf=zeroconf)

    return runner


def test_async_service_update_added_prints_online(
    service_update_runner: Callable[..., ServiceUpdateResult],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """ServiceStateChange.Added prints an ONLINE row with extracted properties."""
    service_update_runner(
        name="myesp._esphomelib._tcp.local.",
        state_change=ServiceStateChange.Added,
        properties={
            b"mac": b"112233445566",
            b"version": b"2024.1.0",
            b"platform": b"ESP32",
            b"board": b"esp32dev",
        },
        ipv4=["192.0.2.10"],
    )
    out = capsys.readouterr().out
    assert "ONLINE" in out
    assert "myesp" in out
    assert "192.0.2.10" in out
    assert "112233445566" in out
    assert "2024.1.0" in out
    assert "ESP32" in out
    assert "esp32dev" in out


def test_async_service_update_removed_prints_offline(
    service_update_runner: Callable[..., ServiceUpdateResult],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """ServiceStateChange.Removed flips the status column to OFFLINE."""
    service_update_runner(state_change=ServiceStateChange.Removed)
    out = capsys.readouterr().out
    assert "OFFLINE" in out
    assert "ONLINE" not in out


def test_async_service_update_missing_properties_show_unknown(
    service_update_runner: Callable[..., ServiceUpdateResult],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing mDNS properties render as 'unknown' rather than empty or 'None'."""
    service_update_runner(properties={})
    out = capsys.readouterr().out
    # Four UNKNOWN columns: mac, version, platform, board.
    assert out.count(UNKNOWN) == 4


def test_async_service_update_no_ipv4_prints_empty_address(
    service_update_runner: Callable[..., ServiceUpdateResult],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When zeroconf returns no IPv4 addresses, the address column is empty."""
    service_update_runner(ipv4=[])
    out = capsys.readouterr().out
    # The FORMAT enforces fixed widths via {:<N}; the address column is left-
    # justified blank when ip_addresses_by_version returns an empty list.
    parts = out.rstrip("\n").split("|")
    address_col = parts[COLUMN_NAMES.index("Address")]
    assert address_col.strip() == ""


def test_async_service_update_sanitizes_hostile_name(
    service_update_runner: Callable[..., ServiceUpdateResult],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A peer-controlled service name with control chars is stripped before printing."""
    service_update_runner(
        name="\x1b[31mevil\nname._esphomelib._tcp.local.",
        state_change=ServiceStateChange.Added,
    )
    out = capsys.readouterr().out
    # ESC and newline are non-printable -> stripped by safe_label_str; the "[31m"
    # ANSI suffix survives as harmless text because only ESC activates a sequence.
    assert "\x1b" not in out
    assert "\n" not in out.rstrip("\n")
    assert "[31mevilname" in out


def test_async_service_update_truncates_long_property_values(
    service_update_runner: Callable[..., ServiceUpdateResult],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each property column truncates to its FORMAT cap so columns can't widen."""
    service_update_runner(
        properties={
            b"mac": b"M" * 100,
            b"version": b"V" * 100,
            b"platform": b"P" * 100,
            b"board": b"B" * 100,
        },
    )
    out = capsys.readouterr().out
    parts = out.rstrip("\n").split("|")
    assert parts[COLUMN_NAMES.index("MAC")].strip() == "M" * _MAX_MAC_DISPLAY
    assert parts[COLUMN_NAMES.index("Version")].strip() == "V" * _MAX_VERSION_DISPLAY
    assert parts[COLUMN_NAMES.index("Platform")].strip() == "P" * _MAX_PLATFORM_DISPLAY
    assert parts[COLUMN_NAMES.index("Board")].strip() == "B" * _MAX_BOARD_DISPLAY


def test_async_service_update_loads_from_cache_synchronously(
    service_update_runner: Callable[..., ServiceUpdateResult],
) -> None:
    """The callback must populate info via load_from_cache (no network I/O)."""
    result = service_update_runner()
    result.info.load_from_cache.assert_called_once_with(result.zeroconf)


# ---------------------------------------------------------------------------
# Tests for main() and cli_entry_point
# ---------------------------------------------------------------------------


@pytest.fixture
def discover_main_runner() -> Callable[[list[str]], Awaitable[dict[str, Any]]]:
    """Drive discover.main once with the zeroconf stack patched out."""

    async def runner(argv: list[str]) -> dict[str, Any]:
        aiozc: AsyncZeroconf = get_mock_async_zeroconf()
        browser = MagicMock()
        browser.async_cancel = AsyncMock()

        captures: dict[str, Any] = {"aiozc": aiozc, "browser": browser}

        def fake_aiozc_cls() -> AsyncZeroconf:
            return aiozc

        def fake_browser_cls(
            zc: Any, service_type: str, *, handlers: list[Any]
        ) -> MagicMock:
            captures["browser_zeroconf"] = zc
            captures["browser_service_type"] = service_type
            captures["browser_handlers"] = handlers
            return browser

        async def fake_event_wait() -> None:
            # Return immediately so main() proceeds to the finally block.
            return None

        with (
            patch("aioesphomeapi.discover.AsyncZeroconf", side_effect=fake_aiozc_cls),
            patch(
                "aioesphomeapi.discover.AsyncServiceBrowser",
                side_effect=fake_browser_cls,
            ),
            patch("asyncio.Event") as mock_event_cls,
        ):
            mock_event_cls.return_value.wait = fake_event_wait
            await main(["aioesphomeapi-discover", *argv])

        browser.async_cancel.assert_awaited_once()
        aiozc.async_close.assert_awaited_once()
        return captures

    return runner


async def test_main_registers_esphomelib_service_browser(
    discover_main_runner: Callable[[list[str]], Awaitable[dict[str, Any]]],
) -> None:
    """main subscribes to the _esphomelib._tcp.local. service type."""
    captures = await discover_main_runner([])
    assert captures["browser_service_type"] == "_esphomelib._tcp.local."
    assert captures["browser_handlers"] == [async_service_update]


async def test_main_prints_header(
    discover_main_runner: Callable[[list[str]], Awaitable[dict[str, Any]]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """main prints the column header row and a separator before subscribing."""
    await discover_main_runner([])
    out = capsys.readouterr().out
    assert FORMAT.format(*COLUMN_NAMES) in out
    assert "-" * 120 in out


@pytest.mark.parametrize(
    ("extra_args", "expected_level"),
    [
        ([], logging.INFO),
        (["--verbose"], logging.DEBUG),
        (["-v"], logging.DEBUG),
    ],
)
async def test_main_configures_log_level_from_verbose_flag(
    discover_main_runner: Callable[[list[str]], Awaitable[dict[str, Any]]],
    extra_args: list[str],
    expected_level: int,
) -> None:
    """main forwards INFO (default) or DEBUG (--verbose / -v) to logging.basicConfig.

    pytest's caplog plugin pre-installs handlers on the root logger, which makes
    logging.basicConfig a no-op — so we assert on the call args, not the live
    level, which is what actually matters for the CLI's behavior.
    """
    with patch("aioesphomeapi.discover.logging.basicConfig") as mock_basic:
        await discover_main_runner(extra_args)
    mock_basic.assert_called_once()
    assert mock_basic.call_args.kwargs["level"] == expected_level


async def test_main_verbose_flag_enables_zeroconf_debug(
    discover_main_runner: Callable[[list[str]], Awaitable[dict[str, Any]]],
) -> None:
    """-v / --verbose elevates the zeroconf logger to DEBUG; default leaves it alone."""
    zc_logger = logging.getLogger("zeroconf")
    saved = zc_logger.level
    try:
        zc_logger.setLevel(logging.NOTSET)
        await discover_main_runner([])
        assert zc_logger.level == logging.NOTSET

        zc_logger.setLevel(logging.NOTSET)
        await discover_main_runner(["--verbose"])
        assert zc_logger.level == logging.DEBUG
    finally:
        zc_logger.setLevel(saved)


def _close_coro(coro: Any) -> None:
    """Close a coroutine so pytest doesn't surface a 'never awaited' warning."""
    coro.close()


def test_cli_entry_point_suppresses_keyboard_interrupt() -> None:
    """cli_entry_point swallows KeyboardInterrupt from asyncio.run."""

    def fake_run(coro: Any) -> None:
        _close_coro(coro)
        raise KeyboardInterrupt

    with patch("aioesphomeapi.discover.asyncio.run", side_effect=fake_run) as mock_run:
        cli_entry_point()  # must not raise
        mock_run.assert_called_once()


def test_cli_entry_point_propagates_other_exceptions() -> None:
    """Non-KeyboardInterrupt exceptions from asyncio.run still surface to the caller."""

    def fake_run(coro: Any) -> None:
        _close_coro(coro)
        raise RuntimeError("boom")

    with (
        patch("aioesphomeapi.discover.asyncio.run", side_effect=fake_run),
        pytest.raises(RuntimeError, match="boom"),
    ):
        cli_entry_point()
