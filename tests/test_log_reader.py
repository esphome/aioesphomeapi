"""Tests for the aioesphomeapi-logs CLI."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aioesphomeapi.api_pb2 import SubscribeLogsResponse  # type: ignore[attr-defined]
from aioesphomeapi.log_reader import main


@pytest.mark.parametrize(
    ("extra_args", "expected_strip"),
    [
        ([], False),
        (["--strip-ansi-escapes"], True),
    ],
)
async def test_strip_ansi_escapes_flag(
    extra_args: list[str], expected_strip: bool
) -> None:
    """The --strip-ansi-escapes flag is forwarded to parse_log_message."""
    captured_kwargs: dict[str, object] = {}

    def fake_parse(text: str, timestamp: str, **kwargs: object) -> tuple[str, ...]:
        captured_kwargs.update(kwargs)
        return (f"{timestamp}{text}",)

    stop = AsyncMock()
    captured: dict[str, object] = {}

    async def fake_async_run(cli, on_log, **kwargs: object) -> AsyncMock:
        captured["on_log"] = on_log
        return stop

    async def fake_event_wait() -> None:
        # Drive one log message through the captured callback, then return so
        # main() proceeds to the finally block instead of blocking forever.
        msg = SubscribeLogsResponse(message=b"hello")
        captured["on_log"](msg)

    with (
        patch("aioesphomeapi.log_reader.async_run", side_effect=fake_async_run),
        patch("aioesphomeapi.log_reader.parse_log_message", side_effect=fake_parse),
        patch("asyncio.Event") as mock_event_cls,
    ):
        mock_event_cls.return_value.wait = fake_event_wait
        await main(["aioesphomeapi-logs", *extra_args, "127.0.0.1"])

    assert captured_kwargs == {"strip_ansi_escapes": expected_strip}
    stop.assert_awaited_once()
