"""Pacing of IR/RF raw timing transmits on the device's completion replies."""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from .api_pb2 import (  # type: ignore[attr-defined]
    InfraredRFTransmitCompleteResponse,
    InfraredRFTransmitRawTimingsRequest,
)

if TYPE_CHECKING:
    import asyncio

    from .connection import APIConnection

# Estimate fallback for firmware before API 1.18: added to the computed frame duration
IR_RF_TRANSMIT_MARGIN = 0.05
# The device answers a frame that never reported 30 s after its air time; a reply the device
# could not send at all (unknown key on a full TCP buffer) never comes, so give up a bit later
IR_RF_TRANSMIT_REPLY_TIMEOUT = 35.0


class IrRfTransmitPacing:
    """Sends the IR/RF transmit requests of one connection one frame at a time.

    Entities can share a transmitter, so the device is the unit of pacing:
    pending[0] is the frame on the wire and the rest wait behind it. Firmware on
    API 1.18 or newer replies once a frame has left the transmitter and the next
    frame goes out on that reply, or when the reply is long overdue so a lost
    reply cannot hold the queue for good. Older firmware never replies, so
    frames are spaced by their computed duration plus a margin instead.
    """

    __slots__ = (
        "_abandoned",
        "_connection",
        "_loop",
        "_pending",
        "_supports_complete",
        "_timer",
    )

    def __init__(
        self,
        connection: APIConnection,
        loop: asyncio.AbstractEventLoop,
        supports_complete: bool,
    ) -> None:
        self._connection = connection
        self._loop = loop
        self._pending: deque[InfraredRFTransmitRawTimingsRequest] = deque()
        self._supports_complete = supports_complete
        self._timer: asyncio.TimerHandle | None = None
        # one expiry handle per frame the timer gave up on: a reply that still comes for it
        # must not pop the frame on the wire now, and a reply that never comes must not
        # swallow the next frame's reply for good
        self._abandoned: deque[asyncio.TimerHandle] = deque()
        if supports_complete:
            connection.add_message_callback(
                self._on_complete, (InfraredRFTransmitCompleteResponse,)
            )

    def send(self, req: InfraredRFTransmitRawTimingsRequest) -> None:
        self._pending.append(req)
        if len(self._pending) == 1:
            self._transmit(req)

    def close(self) -> None:
        """Drop the queue together with the connection it belonged to."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        for handle in self._abandoned:
            handle.cancel()
        self._abandoned.clear()
        self._pending.clear()

    def _transmit(self, req: InfraredRFTransmitRawTimingsRequest) -> None:
        self._connection.send_message(req)
        duration = sum(map(abs, req.timings)) * max(req.repeat_count, 1) / 1_000_000
        grace = (
            IR_RF_TRANSMIT_REPLY_TIMEOUT
            if self._supports_complete
            else IR_RF_TRANSMIT_MARGIN
        )
        self._timer = self._loop.call_later(duration + grace, self._on_timeout)

    def _on_timeout(self) -> None:
        if self._supports_complete:
            self._abandoned.append(
                self._loop.call_later(
                    IR_RF_TRANSMIT_REPLY_TIMEOUT, self._forget_abandoned
                )
            )
        self._advance()

    def _forget_abandoned(self) -> None:
        # the oldest credit is the one whose expiry just fired
        self._abandoned.popleft()

    def _on_complete(self, _msg: InfraredRFTransmitCompleteResponse) -> None:
        if self._abandoned:
            self._abandoned.popleft().cancel()
            return
        if self._timer is not None:
            self._timer.cancel()
        self._advance()

    def _advance(self) -> None:
        self._timer = None
        pending = self._pending
        if pending:
            pending.popleft()
        if pending and self._connection.is_connected:
            self._transmit(pending[0])
