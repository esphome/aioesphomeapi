from __future__ import annotations

import asyncio
import logging
from abc import abstractmethod
from typing import TYPE_CHECKING, Callable, cast

from ..core import SocketClosedAPIError

if TYPE_CHECKING:
    from ..connection import APIConnection

_LOGGER = logging.getLogger(__name__)

SOCKET_ERRORS = (
    ConnectionResetError,
    asyncio.IncompleteReadError,
    OSError,
    TimeoutError,
)


_int = int
_bytes = bytes


class APIFrameHelper:
    """Helper class to handle the API frame protocol."""

    __slots__ = (
        "_loop",
        "_connection",
        "_transport",
        "_writer",
        "ready_future",
        "_buffer",
        "_buffer_len",
        "_pos",
        "_client_info",
        "_log_name",
    )

    def __init__(
        self,
        connection: APIConnection,
        client_info: str,
        log_name: str,
    ) -> None:
        """Initialize the API frame helper."""
        loop = asyncio.get_event_loop()
        self._loop = loop
        self._connection = connection
        self._transport: asyncio.Transport | None = None
        self._writer: None | (Callable[[bytes | bytearray | memoryview], None]) = None
        self.ready_future = self._loop.create_future()
        self._buffer: bytes | None = None
        self._buffer_len = 0
        self._pos = 0
        self._client_info = client_info
        self._log_name = log_name

    def set_log_name(self, log_name: str) -> None:
        """Set the log name."""
        self._log_name = log_name

    def _set_ready_future_exception(self, exc: Exception | type[Exception]) -> None:
        if not self.ready_future.done():
            self.ready_future.set_exception(exc)

    def _add_to_buffer(self, data: bytes | bytearray | memoryview) -> None:
        """Add data to the buffer."""
        # This should not be isinstance(data, bytes) because we want to
        # to explicitly check for bytes and not for subclasses of bytes
        if type(data) is not bytes:  # pylint: disable=unidiomatic-typecheck
            # Protractor sends a bytearray, so we need to convert it to bytes
            # https://github.com/esphome/issues/issues/5117
            bytes_data = bytes(data)
        else:
            bytes_data = data
        if self._buffer_len == 0:
            # This is the best case scenario, we don't have to copy the data
            # and can just use the buffer directly. This is the most common
            # case as well.
            self._buffer = bytes_data
        else:
            if TYPE_CHECKING:
                assert self._buffer is not None, "Buffer should be set"
            # This is the worst case scenario, we have to copy the bytes_data
            # and can't just use the buffer directly. This is also very
            # uncommon since we usually read the entire frame at once.
            self._buffer += bytes_data
        self._buffer_len += len(bytes_data)

    def _remove_from_buffer(self) -> None:
        """Remove data from the buffer."""
        end_of_frame_pos = self._pos
        self._buffer_len -= end_of_frame_pos
        if self._buffer_len == 0:
            # This is the best case scenario, we can just set the buffer to None
            # and don't have to copy the data. This is the most common case as well.
            self._buffer = None
            return
        if TYPE_CHECKING:
            assert self._buffer is not None, "Buffer should be set"
        # This is the worst case scenario, we have to copy the data
        # and can't just use the buffer directly. This should only happen
        # when we read multiple frames at once because the event loop
        # is blocked and we cannot pull the data out of the buffer fast enough.
        self._buffer = self._buffer[end_of_frame_pos:]

    def _read(self, length: _int) -> bytes | None:
        """Read exactly length bytes from the buffer or None if all the bytes are not yet available."""
        original_pos = self._pos
        new_pos = original_pos + length
        if self._buffer_len < new_pos:
            return None
        self._pos = new_pos
        if TYPE_CHECKING:
            assert self._buffer is not None, "Buffer should be set"
        return self._buffer[original_pos:new_pos]

    def _read_varuint(self) -> _int:
        """Read a varuint from the buffer or -1 if the buffer runs out of bytes."""
        if TYPE_CHECKING:
            assert self._buffer is not None, "Buffer should be set"
        result = 0
        bitpos = 0
        while self._buffer_len > self._pos:
            val = self._buffer[self._pos]
            self._pos += 1
            result |= (val & 0x7F) << bitpos
            if (val & 0x80) == 0:
                return result
            bitpos += 7
        return -1

    @abstractmethod
    def write_packets(
        self, packets: list[tuple[int, bytes]], debug_enabled: bool
    ) -> None:
        """Write a packets to the socket.

        Packets are in the format of tuple[protobuf_type, protobuf_data]
        """

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a new connection."""
        self._transport = cast(asyncio.Transport, transport)
        self._writer = self._transport.write

    def _handle_error_and_close(self, exc: Exception) -> None:
        self._handle_error(exc)
        self.close()

    def _handle_error(self, exc: Exception) -> None:
        self._set_ready_future_exception(exc)
        self._connection.report_fatal_error(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        """Handle the connection being lost."""
        self._handle_error(
            exc or SocketClosedAPIError(f"{self._log_name}: Connection lost")
        )

    def eof_received(self) -> bool | None:
        """Handle EOF received."""
        self._handle_error(SocketClosedAPIError(f"{self._log_name}: EOF received"))
        return False

    def close(self) -> None:
        """Close the connection."""
        if self._transport:
            self._transport.close()
            self._transport = None
            self._writer = None

    def pause_writing(self) -> None:
        """Stub."""

    def resume_writing(self) -> None:
        """Stub."""

    def _write_bytes(self, data: _bytes, debug_enabled: bool) -> None:
        """Write bytes to the socket."""
        if debug_enabled:
            _LOGGER.debug("%s: Sending frame: [%s]", self._log_name, data.hex())

        if TYPE_CHECKING:
            assert self._writer is not None, "Writer is not set"

        self._writer(data)
