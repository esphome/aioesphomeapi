from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from ..core import ProtocolAPIError, RequiresEncryptionAPIError
from .base import APIFrameHelper
from .packets import make_plain_text_packets

_int = int

# Cap at 4 bytes so the decoded value (max 2**28 - 1) always fits in a signed
# 32-bit int. Under Cython, `result` is `unsigned int` and the function returns
# `int`; a 5-byte varuint could decode to a value >= 2**31 that would cast to a
# *negative* int and silently hit the < 0 sentinel branch in data_received,
# leaving the buffer-growth DoS open. 4 bytes is well above any value used by
# the protocol (length is capped at 65535 = 17 bits; msg_type fits in 1 byte).
_MAX_VARUINT_BYTES = 4
# bitpos is incremented by 7 after each continuation byte, so 28 bits means we
# have already consumed 4 continuation bytes — one more would be the 5th byte.
_MAX_VARUINT_BITPOS = 7 * _MAX_VARUINT_BYTES

# Bounds the per-frame allocation a peer can request via the length varuint.
# Matches the firmware's uint16_t wire-format max (65535), which is the same
# absolute cap the noise path gets for free from its fixed 16-bit length header.
# MAX_PLAINTEXT_FRAME_SIZE is the Python-importable form (used by tests);
# _MAX_PLAINTEXT_FRAME_SIZE is the cdef int form used internally per .pxd.
MAX_PLAINTEXT_FRAME_SIZE = 65535
_MAX_PLAINTEXT_FRAME_SIZE = MAX_PLAINTEXT_FRAME_SIZE

# _read_varuint return sentinels (negative because varuints are non-negative).
_VARUINT_INCOMPLETE = -1
_VARUINT_PROTOCOL_ERROR = -2


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
        self._write_bytes(make_plain_text_packets(packets), debug_enabled)

    def _read_varuint(self) -> _int:
        """Read a varuint from the buffer.

        Pure C path with no Python calls. Returns one of:
          * the decoded value (>= 0), if a complete varuint was read;
          * _VARUINT_INCOMPLETE, if the buffer ran out mid-varuint;
          * _VARUINT_PROTOCOL_ERROR, if the varuint exceeds
            _MAX_VARUINT_BYTES (the caller is responsible for closing the
            connection).

        Callers must check for both sentinels explicitly rather than
        treating any negative value generically.
        """
        if TYPE_CHECKING:
            assert self._buffer is not None, "Buffer should be set"
        result = 0
        bitpos = 0
        cstr = self._buffer
        while self._buffer_len > self._pos:
            val = cstr[self._pos]
            self._pos += 1
            result |= (val & 0x7F) << bitpos
            if (val & 0x80) == 0:
                return result
            bitpos += 7
            # Check after the byte read so the common 1-byte varuint path
            # (high bit unset on the first byte) skips this branch entirely.
            if bitpos >= _MAX_VARUINT_BITPOS:
                return _VARUINT_PROTOCOL_ERROR
        return _VARUINT_INCOMPLETE

    def _close_on_oversized_varuint(self) -> None:
        """Close the connection on a varuint that exceeds the byte cap."""
        self._handle_error_and_close(
            ProtocolAPIError(
                f"{self._log_name}: varuint exceeds {_MAX_VARUINT_BYTES}-byte limit"
            )
        )

    def data_received(self, data: bytes | bytearray | memoryview) -> None:
        self._add_to_buffer(data)
        # Message header is at least 3 bytes, empty length allowed
        while self._buffer_len >= 3:
            self._pos = 0
            # _read_varuint is pure C and returns either a non-negative
            # decoded value or one of the two negative sentinels —
            # _VARUINT_INCOMPLETE (wait for more data) or
            # _VARUINT_PROTOCOL_ERROR (varuint too long; close the
            # connection here since _read_varuint can't safely call into
            # Python from a noexcept cdef path).
            preamble = self._read_varuint()
            if preamble != 0x00:
                if preamble == _VARUINT_PROTOCOL_ERROR:
                    self._close_on_oversized_varuint()
                    return
                if preamble == _VARUINT_INCOMPLETE:
                    return
                self._error_on_incorrect_preamble(preamble)
                return
            length = self._read_varuint()
            if length == _VARUINT_PROTOCOL_ERROR:
                self._close_on_oversized_varuint()
                return
            if length == _VARUINT_INCOMPLETE:
                return
            if length > _MAX_PLAINTEXT_FRAME_SIZE:
                self._handle_error_and_close(
                    ProtocolAPIError(
                        f"{self._log_name}: frame length {length} exceeds "
                        f"{_MAX_PLAINTEXT_FRAME_SIZE}-byte limit"
                    )
                )
                return
            msg_type = self._read_varuint()
            if msg_type == _VARUINT_PROTOCOL_ERROR:
                self._close_on_oversized_varuint()
                return
            if msg_type == _VARUINT_INCOMPLETE:
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
            if (packet_data := self._read(length)) is None:
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
            ProtocolAPIError(f"{self._log_name}: Invalid preamble 0x{preamble:02x}")
        )
