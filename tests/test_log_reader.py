"""Tests for the aioesphomeapi-logs CLI."""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from aioesphomeapi.api_pb2 import SubscribeLogsResponse  # type: ignore[attr-defined]
from aioesphomeapi.log_reader import main


async def _run_main(argv: list[str], log_message: bytes = b"hello") -> dict[str, Any]:
    """Drive log_reader.main once with a single fake log message and return captures.

    Returns a dict with the kwargs captured from async_run, the args/kwargs
    captured from APIClient, the kwargs captured from parse_log_message, and
    the parse_log_message call args (text, timestamp).
    """
    parse_kwargs: dict[str, Any] = {}
    parse_args: dict[str, Any] = {}
    runner_kwargs: dict[str, Any] = {}
    client_args: dict[str, Any] = {}
    stop = AsyncMock()
    on_log_holder: dict[str, Any] = {}

    def fake_parse(text: str, timestamp: str, **kwargs: Any) -> tuple[str, ...]:
        parse_args["text"] = text
        parse_args["timestamp"] = timestamp
        parse_kwargs.update(kwargs)
        return (f"{timestamp}{text}",)

    async def fake_async_run(cli: Any, on_log: Any, **kwargs: Any) -> AsyncMock:
        runner_kwargs.update(kwargs)
        on_log_holder["on_log"] = on_log
        return stop

    def fake_client(*args: Any, **kwargs: Any) -> Any:
        client_args["args"] = args
        client_args["kwargs"] = kwargs
        return object()

    async def fake_event_wait() -> None:
        msg = SubscribeLogsResponse(message=log_message)
        on_log_holder["on_log"](msg)

    with (
        patch("aioesphomeapi.log_reader.APIClient", side_effect=fake_client),
        patch("aioesphomeapi.log_reader.async_run", side_effect=fake_async_run),
        patch("aioesphomeapi.log_reader.parse_log_message", side_effect=fake_parse),
        patch("asyncio.Event") as mock_event_cls,
    ):
        mock_event_cls.return_value.wait = fake_event_wait
        await main(["aioesphomeapi-logs", *argv])

    stop.assert_awaited_once()
    return {
        "parse_kwargs": parse_kwargs,
        "parse_args": parse_args,
        "runner_kwargs": runner_kwargs,
        "client_args": client_args,
    }


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
    captures = await _run_main([*extra_args, "127.0.0.1"])
    assert captures["parse_kwargs"] == {"strip_ansi_escapes": expected_strip}


@pytest.mark.parametrize(
    ("extra_args", "expected_subscribe_states"),
    [
        ([], True),
        (["--no-states"], False),
    ],
)
async def test_no_states_flag(
    extra_args: list[str], expected_subscribe_states: bool
) -> None:
    """The --no-states flag toggles subscribe_states forwarded to async_run."""
    captures = await _run_main([*extra_args, "127.0.0.1"])
    assert captures["runner_kwargs"]["subscribe_states"] is expected_subscribe_states


@pytest.mark.parametrize(
    ("extra_args", "expected_allow_fallback"),
    [
        ([], False),
        (["--allow-plaintext-fallback"], True),
    ],
)
async def test_allow_plaintext_fallback_flag(
    extra_args: list[str], expected_allow_fallback: bool
) -> None:
    """The --allow-plaintext-fallback flag is forwarded to async_run."""
    captures = await _run_main([*extra_args, "127.0.0.1"])
    assert (
        captures["runner_kwargs"]["allow_plaintext_fallback"] is expected_allow_fallback
    )


async def test_apiclient_receives_address_and_default_port() -> None:
    """The positional address and default port are passed to APIClient."""
    captures = await _run_main(["192.0.2.5"])
    args = captures["client_args"]["args"]
    kwargs = captures["client_args"]["kwargs"]
    assert args[0] == "192.0.2.5"
    assert args[1] == 6053
    assert kwargs == {"password": None, "noise_psk": None, "keepalive": 10}


async def test_apiclient_receives_custom_port_password_and_psk() -> None:
    """--port, --password, --noise-psk are forwarded to APIClient."""
    captures = await _run_main(
        [
            "--port",
            "1234",
            "--password",
            "secret",
            "--noise-psk",
            "abc=",
            "127.0.0.1",
        ]
    )
    args = captures["client_args"]["args"]
    kwargs = captures["client_args"]["kwargs"]
    assert args[0] == "127.0.0.1"
    assert args[1] == 1234
    assert kwargs == {"password": "secret", "noise_psk": "abc=", "keepalive": 10}


async def test_on_log_decodes_invalid_utf8_without_raising() -> None:
    """Malformed UTF-8 bytes survive via backslashreplace and reach parse_log_message."""
    captures = await _run_main(["127.0.0.1"], log_message=b"hello \xff world")
    # backslashreplace turns the invalid byte into "\xff" rather than raising.
    assert captures["parse_args"]["text"] == "hello \\xff world"


async def test_on_log_timestamp_format() -> None:
    """The timestamp passed to parse_log_message is bracketed HH:MM:SS.mmm."""
    captures = await _run_main(["127.0.0.1"])
    ts = captures["parse_args"]["timestamp"]
    assert isinstance(ts, str)
    assert re.fullmatch(r"\[\d{2}:\d{2}:\d{2}\.\d{3}\]", ts), ts
