"""Shared helpers for the benchmark suite."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import Any

from google.protobuf import message

from aioesphomeapi import APIConnection
from aioesphomeapi.client import APIClient
from aioesphomeapi.client_base import on_state_msg


def noop(msg: object) -> None:
    """No-op message callback."""


def make_connection() -> APIConnection:
    """Build an APIConnection suitable for benchmarking process_packet."""
    client = APIClient("fake.address", 6052, None)
    return APIConnection(client._params, lambda expected_disconnect: None, False, None)


def bench_process_packet(
    msg: message.Message,
    msg_type: int,
    handler: Callable[[Any], None] | None = None,
) -> Callable[[], None]:
    """Return a 0-arg callable that drives APIConnection.process_packet.

    A fresh connection is created and ``handler`` (default: no-op) is
    registered for the message's protobuf type. Bytes are serialized once;
    each invocation only exercises the receive path.
    """
    data = msg.SerializeToString()
    connection = make_connection()
    connection.add_message_callback(handler or noop, (type(msg),))
    return partial(connection.process_packet, msg_type, data)


def bench_state_process_packet(
    msg: message.Message, msg_type: int
) -> Callable[[], None]:
    """Build a process_packet bench wired through ``on_state_msg``.

    Mirrors what ``APIClient.subscribe_states`` does, so the benchmark covers
    the full user-visible path from packet bytes to ``EntityState`` object.
    """
    return bench_process_packet(msg, msg_type, partial(on_state_msg, noop, {}))
