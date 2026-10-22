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

    A reply carries only the entity's key and device id, not a request id. If
    the device answers a frame later than the grace timeout and the next frame
    queued is for the same entity, that late reply releases the next frame
    early; the device answers within 30 s of a frame's air time, so this needs
    a reply more than 5 s late.
    """

    __slots__ = ("_connection", "_loop", "_pending", "_supports_complete", "_timer")

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
        self._pending.clear()

    def _transmit(self, req: InfraredRFTransmitRawTimingsRequest) -> None:
        self._connection.send_message(req)
        duration = sum(map(abs, req.timings)) * max(req.repeat_count, 1) / 1_000_000
        grace = (
            IR_RF_TRANSMIT_REPLY_TIMEOUT
            if self._supports_complete
            else IR_RF_TRANSMIT_MARGIN
        )
        self._timer = self._loop.call_later(duration + grace, self._advance)

    def _on_complete(self, msg: InfraredRFTransmitCompleteResponse) -> None:
        pending = self._pending
        if not pending:
            return
        # the reply echoes the request's key; one for a frame the timer already gave up on
        # must not release the frame on the wire now
        on_wire = pending[0]
        if msg.key != on_wire.key or msg.device_id != on_wire.device_id:
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
