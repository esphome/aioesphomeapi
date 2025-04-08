from __future__ import annotations

import asyncio
from functools import lru_cache
from typing import TYPE_CHECKING

from ..core import ProtocolAPIError, RequiresEncryptionAPIError
from .base import APIFrameHelper

_int = int
_bytes = bytes


def _varuint_to_bytes(value: _int) -> bytes:
    """Convert a varuint to bytes."""
    if value <= 0x7F:
        return bytes((value,))

    result = bytearray()
    while value:
        temp = value & 0x7F
        value >>= 7
        if value:
            result.append(temp | 0x80)
        else:
            result.append(temp)

    return bytes(result)


_cached_varuint_to_bytes = lru_cache(maxsize=1024)(_varuint_to_bytes)
varuint_to_bytes = _cached_varuint_to_bytes


class APIPlaintextFrameHelper(APIFrameHelper):
    """Frame helper for plaintext API connections."""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a new connection."""
        super().connection_made(transport)
        self.ready_future.set_result(None)

    def write_packets(
        self, packets: list[tuple[int, bytes]], debug_enabled: bool
    ) -> None:
        """Write a packets to the socket.

        Packets are in the format of tuple[protobuf_type, protobuf_data]

        The entire packet must be written in a single call.
        """
        out: list[bytes] = []
        for packet in packets:
            type_: int = packet[0]
            data: bytes = packet[1]
            out.append(b"\0")
            out.append(varuint_to_bytes(len(data)))
            out.append(varuint_to_bytes(type_))
            if data:
                out.append(data)

        self._write_bytes(out, debug_enabled)

    def _read_varuint(self, cbuffer: _bytes) -> _int:
        """Read a varuint from the buffer or -1 if the buffer runs out of bytes."""
        result = 0
        bitpos = 0
        while self._buffer_len > self._pos:
            val = cbuffer[self._pos]
            self._pos += 1
            result |= (val & 0x7F) << bitpos
            if (val & 0x80) == 0:
                return result
            bitpos += 7
        return -1

    def data_received(self, data: bytes | bytearray | memoryview) -> None:
        self._add_to_buffer(data)
        # Message header is at least 3 bytes, empty length allowed
        while self._buffer_len >= 3:
            if TYPE_CHECKING:
                assert self._buffer is not None, "Buffer should be set"
            self._pos = 0
            cbuffer = self._buffer
            # Read preamble, which should always 0x00
            if (preamble := self._read_varuint(cbuffer)) != 0x00:
                self._error_on_incorrect_preamble(preamble)
                return
            if (length := self._read_varuint(cbuffer)) == -1:
                return
            if (msg_type := self._read_varuint(cbuffer)) == -1:
                return

            if length == 0:
                self._remove_from_buffer()
                self._connection.process_packet(msg_type, b"")
                continue

            # The packet data is not yet available, wait for more data
            # to arrive before continuing, since callback_packet has not
            # been called yet the buffer will not be cleared and the next
            # call to data_received will continue processing the packet
            # at the start of the frame.
            if (packet_data := self._read(length, cbuffer)) is None:
                return
            self._remove_from_buffer()
            self._connection.process_packet(msg_type, packet_data)
            # If we have more data, continue processing

    def _error_on_incorrect_preamble(self, preamble: _int) -> None:
        """Handle an incorrect preamble."""
        if preamble == 0x01:
            self._handle_error_and_close(
                RequiresEncryptionAPIError(
                    f"{self._log_name}: Connection requires encryption"
                )
            )
            return
        self._handle_error_and_close(
            ProtocolAPIError(f"{self._log_name}: Invalid preamble {preamble:02x}")
        )
