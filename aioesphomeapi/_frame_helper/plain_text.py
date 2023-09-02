from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ..core import ProtocolAPIError, RequiresEncryptionAPIError, SocketAPIError
from ..util import bytes_to_varuint, varuint_to_bytes
from .base import WRITE_EXCEPTIONS, APIFrameHelper

_LOGGER = logging.getLogger(__name__)


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

    def data_received(self, data: bytes) -> None:  # pylint: disable=too-many-branches
        self._buffer += data
        self._buffer_len += len(data)
        while self._buffer:
            # Read preamble, which should always 0x00
            # Also try to get the length and msg type
            # to avoid multiple calls to _read_exactly
            self._pos = 0
            init_bytes = self._read_exactly(3)
            if init_bytes is None:
                return
            msg_type_int: int | None = None
            length_int: int | None = None
            preamble, length_high, maybe_msg_type = init_bytes
            if preamble != 0x00:
                if preamble == 0x01:
                    self._handle_error_and_close(
                        RequiresEncryptionAPIError(
                            f"{self._log_name}: Connection requires encryption"
                        )
                    )
                    return
                self._handle_error_and_close(
                    ProtocolAPIError(
                        f"{self._log_name}: Invalid preamble {preamble:02x}"
                    )
                )
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
                    msg_type = bytes(init_bytes[2:3])
            else:
                # Length is longer than 1 byte
                length = bytes(init_bytes[1:3])
                # If the message is long, we need to read the rest of the length
                while length[-1] & 0x80 == 0x80:
                    add_length = self._read_exactly(1)
                    if add_length is None:
                        return
                    length += add_length
                length_int = bytes_to_varuint(length)
                # Since the length is longer than 1 byte we do not have the
                # message type yet.
                msg_type = b""

            # If the we do not have the message type yet because the message
            # length was so long it did not fit into the first byte we need
            # to read the (rest) of the message type
            if msg_type_int is None:
                while not msg_type or msg_type[-1] & 0x80 == 0x80:
                    add_msg_type = self._read_exactly(1)
                    if add_msg_type is None:
                        return
                    msg_type += add_msg_type
                msg_type_int = bytes_to_varuint(msg_type)

            if TYPE_CHECKING:
                assert length_int is not None
                assert msg_type_int is not None

            if length_int == 0:
                packet_data = b""
            else:
                packet_data_bytearray = self._read_exactly(length_int)
                # The packet data is not yet available, wait for more data
                # to arrive before continuing, since callback_packet has not
                # been called yet the buffer will not be cleared and the next
                # call to data_received will continue processing the packet
                # at the start of the frame.
                if packet_data_bytearray is None:
                    return
                packet_data = bytes(packet_data_bytearray)

            end_of_frame_pos = self._pos
            del self._buffer[:end_of_frame_pos]
            self._buffer_len -= end_of_frame_pos
            self._on_pkt(msg_type_int, packet_data)
            # If we have more data, continue processing
