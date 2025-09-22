"""Tests for timezone detection utilities."""

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from aioesphomeapi.singleton import _SINGLETON_CACHE
from aioesphomeapi.timezone import (
    _extract_tz_string,
    _get_local_timezone,
    _load_tzdata,
    get_local_timezone,
    get_timezone,
    iana_to_posix_tz,
)


@pytest.fixture(autouse=True)
def clear_caches() -> None:
    """Clear caches before and after each test."""
    _SINGLETON_CACHE.clear()
    _get_local_timezone.cache_clear()
    yield
    _SINGLETON_CACHE.clear()
    _get_local_timezone.cache_clear()


def test_extract_tz_string_valid() -> None:
    """Test extracting TZ string from valid tzdata."""
    # Sample tzdata file content with TZ string on second-to-last line
    tzdata = b"TZif2\x00\x00\x00\x00\x00\x00\x00\nCST6CDT,M3.2.0,M11.1.0\n"
    result = _extract_tz_string(tzdata)
    assert result == "CST6CDT,M3.2.0,M11.1.0"


def test_extract_tz_string_empty() -> None:
    """Test extracting TZ string from empty data."""
    tzdata = b""
    result = _extract_tz_string(tzdata)
    assert result == ""


def test_extract_tz_string_invalid_utf8() -> None:
    """Test extracting TZ string with invalid UTF-8."""
    tzdata = b"\xff\xfe\n\xff\xfe\n"
    result = _extract_tz_string(tzdata)
    assert result == ""


def test_load_tzdata_invalid_key() -> None:
    """Test loading tzdata with invalid IANA key."""
    result = _load_tzdata("invalid")
    assert result is None

    result = _load_tzdata("")
    assert result is None


@patch("aioesphomeapi.timezone.resources.files")
def test_load_tzdata_file_not_found(mock_files) -> None:
    """Test loading tzdata when file doesn't exist."""
    mock_files.side_effect = FileNotFoundError()
    result = _load_tzdata("America/Chicago")
    assert result is None


@patch("aioesphomeapi.timezone.resources.files")
def test_load_tzdata_success(mock_files) -> None:
    """Test successful tzdata loading."""
    mock_resource = MagicMock()
    mock_resource.read_bytes.return_value = b"tzdata_content"
    mock_files.return_value.__truediv__.return_value = mock_resource

    result = _load_tzdata("America/Chicago")
    assert result == b"tzdata_content"
    mock_files.assert_called_with("tzdata.zoneinfo.America")


@patch("aioesphomeapi.timezone.tzlocal.get_localzone_name")
@patch("aioesphomeapi.timezone._load_tzdata")
@patch("aioesphomeapi.timezone._extract_tz_string")
def test_get_local_timezone_sync_success(mock_extract, mock_load, mock_tzlocal) -> None:
    """Test successful synchronous timezone detection."""
    mock_tzlocal.return_value = "America/Chicago"
    mock_load.return_value = b"tzdata"
    mock_extract.return_value = "CST6CDT,M3.2.0,M11.1.0"

    result = _get_local_timezone()
    assert result == "CST6CDT,M3.2.0,M11.1.0"

    # Should be cached
    result2 = _get_local_timezone()
    assert result2 == "CST6CDT,M3.2.0,M11.1.0"

    # Verify function was only called once due to cache
    assert mock_tzlocal.call_count == 1


@patch("aioesphomeapi.timezone.tzlocal.get_localzone_name")
def test_get_local_timezone_sync_no_timezone(mock_tzlocal) -> None:
    """Test when system timezone cannot be determined."""
    mock_tzlocal.return_value = None

    result = _get_local_timezone()
    assert result == ""


@patch("aioesphomeapi.timezone.tzlocal.get_localzone_name")
@patch("aioesphomeapi.timezone._load_tzdata")
def test_get_local_timezone_sync_already_tz_string(mock_load, mock_tzlocal) -> None:
    """Test when tzlocal returns a TZ string directly."""
    mock_tzlocal.return_value = "EST5EDT,M3.2.0,M11.1.0"
    mock_load.return_value = None  # Indicates it's not an IANA key

    result = _get_local_timezone()
    assert result == "EST5EDT,M3.2.0,M11.1.0"


@patch("aioesphomeapi.timezone.tzlocal.get_localzone_name")
def test_get_local_timezone_sync_exception(mock_tzlocal) -> None:
    """Test exception handling in timezone detection."""
    mock_tzlocal.side_effect = Exception("Test error")

    result = _get_local_timezone()
    assert result == ""


async def test_get_local_timezone_async() -> None:
    """Test async timezone detection."""
    with patch("aioesphomeapi.timezone._get_local_timezone") as mock_sync:
        mock_sync.return_value = "CST6CDT,M3.2.0,M11.1.0"

        result = await get_local_timezone()
        assert result == "CST6CDT,M3.2.0,M11.1.0"

        # Should be cached via singleton
        result2 = await get_local_timezone()
        assert result2 == "CST6CDT,M3.2.0,M11.1.0"

        # Verify the sync function was only called once
        assert mock_sync.call_count == 1


async def test_get_local_timezone_async_simultaneous() -> None:
    """Test that simultaneous async calls are handled properly."""
    call_count = 0

    def mock_sync_timezone() -> str:
        nonlocal call_count
        call_count += 1
        # Simulate slow I/O with a sleep

        time.sleep(0.01)
        return "CST6CDT,M3.2.0,M11.1.0"

    with patch("aioesphomeapi.timezone._get_local_timezone", mock_sync_timezone):
        # Start two tasks simultaneously
        task1 = asyncio.create_task(get_local_timezone())
        task2 = asyncio.create_task(get_local_timezone())

        # Wait for both tasks
        result1 = await task1
        result2 = await task2

        assert result1 == "CST6CDT,M3.2.0,M11.1.0"
        assert result2 == "CST6CDT,M3.2.0,M11.1.0"

        # Function should only be called once despite simultaneous calls
        assert call_count == 1


async def test_get_local_timezone_async_empty_result() -> None:
    """Test async timezone detection with empty result."""
    with patch("aioesphomeapi.timezone._get_local_timezone") as mock_sync:
        mock_sync.return_value = ""

        result = await get_local_timezone()
        assert result == ""


def test_real_timezone_detection() -> None:
    """Test that real timezone detection works (integration test)."""
    # This test will use the actual system timezone
    result = _get_local_timezone()

    # Should return a non-empty string on most systems
    # We can't assert a specific value as it depends on the system
    assert isinstance(result, str)

    # If a timezone was detected, it should follow POSIX TZ format patterns
    if result:
        # Basic validation - should contain timezone abbreviations and/or offsets
        # Examples: "CST6CDT,M3.2.0,M11.1.0", "PST8PDT,M3.2.0,M11.1.0", "GMT0", etc.
        assert len(result) > 0
        # Should be ASCII
        assert result.isascii()


@patch("aioesphomeapi.timezone._load_tzdata")
@patch("aioesphomeapi.timezone._extract_tz_string")
def test_iana_to_posix_tz_success(mock_extract, mock_load) -> None:
    """Test successful IANA to POSIX conversion."""
    mock_load.return_value = b"tzdata"
    mock_extract.return_value = "CST6CDT,M3.2.0,M11.1.0"

    result = iana_to_posix_tz("America/Chicago")
    assert result == "CST6CDT,M3.2.0,M11.1.0"

    result2 = iana_to_posix_tz("America/Chicago")
    assert result2 == "CST6CDT,M3.2.0,M11.1.0"

    assert mock_load.call_count == 2


@patch("aioesphomeapi.timezone._load_tzdata")
def test_iana_to_posix_tz_invalid_iana(mock_load) -> None:
    """Test when input is not a valid IANA key."""
    mock_load.return_value = None  # Indicates it's not an IANA key

    result = iana_to_posix_tz("InvalidTimezone")
    assert result == ""


@patch("aioesphomeapi.timezone._load_tzdata")
def test_iana_to_posix_tz_exception(mock_load) -> None:
    """Test that exceptions bubble up from IANA conversion."""
    mock_load.side_effect = Exception("Test error")

    with pytest.raises(Exception, match="Test error"):
        iana_to_posix_tz("America/Chicago")


async def test_get_timezone_with_iana_key() -> None:
    """Test get_timezone with IANA key."""
    with patch("aioesphomeapi.timezone.iana_to_posix_tz") as mock_convert:
        mock_convert.return_value = "CST6CDT,M3.2.0,M11.1.0"

        result = await get_timezone("America/Chicago")
        assert result == "CST6CDT,M3.2.0,M11.1.0"

        mock_convert.assert_called_once_with("America/Chicago")


async def test_get_timezone_without_key() -> None:
    """Test get_timezone without IANA key (local detection)."""
    with patch("aioesphomeapi.timezone._get_local_timezone") as mock_local:
        mock_local.return_value = "PST8PDT,M3.2.0,M11.1.0"

        result = await get_timezone(None)
        assert result == "PST8PDT,M3.2.0,M11.1.0"

        mock_local.assert_called_once()


async def test_get_timezone_with_empty_key() -> None:
    """Test get_timezone with empty string (should use local)."""
    with patch("aioesphomeapi.timezone._get_local_timezone") as mock_local:
        mock_local.return_value = "EST5EDT,M3.2.0,M11.1.0"

        result = await get_timezone("")
        assert result == "EST5EDT,M3.2.0,M11.1.0"

        mock_local.assert_called_once()


async def test_get_timezone_caching() -> None:
    """Test that get_timezone properly caches IANA timezone conversions."""
    call_count = 0

    def mock_convert(key: str) -> str:
        nonlocal call_count
        call_count += 1
        return "CST6CDT,M3.2.0,M11.1.0"

    with patch("aioesphomeapi.timezone.iana_to_posix_tz", mock_convert):
        # First call
        result1 = await get_timezone("America/Chicago")
        assert result1 == "CST6CDT,M3.2.0,M11.1.0"

        # Second call with same key - should be cached
        result2 = await get_timezone("America/Chicago")
        assert result2 == "CST6CDT,M3.2.0,M11.1.0"

        # Should only be called once due to singleton caching
        assert call_count == 1

        # Different timezone should trigger another call
        result3 = await get_timezone("Europe/London")
        assert result3 == "CST6CDT,M3.2.0,M11.1.0"  # Mock returns same value
        assert call_count == 2
