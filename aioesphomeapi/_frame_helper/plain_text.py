from __future__ import annotations

import asyncio
import logging
from functools import lru_cache
from typing import TYPE_CHECKING

from ..core import ProtocolAPIError, RequiresEncryptionAPIError, SocketAPIError
from .base import WRITE_EXCEPTIONS, APIFrameHelper

_LOGGER = logging.getLogger(__name__)

_int = int
_bytes = bytes


def _varuint_to_bytes(value: _int) -> bytes:
    """Convert a varuint to bytes."""
    if value <= 0x7F:
        return bytes((value,))

    result = []
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


def _bytes_to_varuint(value: _bytes) -> _int | None:
    """Convert bytes to a varuint."""
    result = 0
    bitpos = 0
    for val in value:
        result |= (val & 0x7F) << bitpos
        if (val & 0x80) == 0:
            return result
        bitpos += 7
    return None


_cached_bytes_to_varuint = lru_cache(maxsize=1024)(_bytes_to_varuint)
bytes_to_varuint = _cached_bytes_to_varuint


class APIPlaintextFrameHelper(APIFrameHelper):
    """Frame helper for plaintext API connections."""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a new connection."""
        super().connection_made(transport)
        self._ready_future.set_result(None)

    def write_packet(self, type_: int, data: bytes) -> None:
        """Write a packet to the socket.

        The entire packet must be written in a single call.
        """
        if TYPE_CHECKING:
            assert self._writer is not None, "Writer should be set"

        data = b"\0" + varuint_to_bytes(len(data)) + varuint_to_bytes(type_) + data
        if self._debug_enabled():
            _LOGGER.debug("%s: Sending plaintext frame %s", self._log_name, data.hex())

        try:
            self._writer(data)
        except WRITE_EXCEPTIONS as err:
            raise SocketAPIError(
                f"{self._log_name}: Error while writing data: {err}"
            ) from err

    def data_received(  # pylint: disable=too-many-branches,too-many-return-statements
        self, data: bytes
    ) -> None:
        self._add_to_buffer(data)
        while self._buffer:
            # Read preamble, which should always 0x00
            # Also try to get the length and msg type
            # to avoid multiple calls to _read_exactly
            self._pos = 0
            if (init_bytes := self._read_exactly(3)) is None:
                return
            msg_type_int: int | None = None
            length_int = 0
            preamble = init_bytes[0]
            length_high = init_bytes[1]
            maybe_msg_type = init_bytes[2]
            if preamble != 0x00:
                self._error_on_incorrect_preamble(preamble)
                return

            if length_high & 0x80 != 0x80:
                # Length is only 1 byte
                #
                # This is the most common case needing a single byte for
                # length and type which means we avoid 2 calls to _read_exactly
                length_int = length_high
                if maybe_msg_type & 0x80 != 0x80:
                    # Message type is also only 1 byte
                    msg_type_int = maybe_msg_type
                else:
                    # Message type is longer than 1 byte
                    msg_type = init_bytes[2:3]
            else:
                # Length is longer than 1 byte
                length = init_bytes[1:3]
                # If the message is long, we need to read the rest of the length
                while length[-1] & 0x80 == 0x80:
                    if (add_length := self._read_exactly(1)) is None:
                        return
                    length += add_length
                length_int = bytes_to_varuint(length) or 0
                # Since the length is longer than 1 byte we do not have the
                # message type yet.
                if (msg_type_byte := self._read_exactly(1)) is None:
                    return
                msg_type = msg_type_byte
                if msg_type[-1] & 0x80 != 0x80:
                    # Message type is only 1 byte
                    msg_type_int = msg_type[0]

            # If the we do not have the message type yet because the message
            # length was so long it did not fit into the first byte we need
            # to read the (rest) of the message type
            if msg_type_int is None:
                while msg_type[-1] & 0x80 == 0x80:
                    if (add_msg_type := self._read_exactly(1)) is None:
                        return
                    msg_type += add_msg_type
                msg_type_int = bytes_to_varuint(msg_type)

            if TYPE_CHECKING:
                assert msg_type_int is not None

            if length_int == 0:
                packet_data = b""
            else:
                # The packet data is not yet available, wait for more data
                # to arrive before continuing, since callback_packet has not
                # been called yet the buffer will not be cleared and the next
                # call to data_received will continue processing the packet
                # at the start of the frame.
                if (maybe_packet_data := self._read_exactly(length_int)) is None:
                    return
                packet_data = maybe_packet_data

            self._remove_from_buffer()
            self._on_pkt(msg_type_int, packet_data)
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
