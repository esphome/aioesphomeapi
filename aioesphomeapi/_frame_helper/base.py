from __future__ import annotations

import asyncio
import logging
from abc import abstractmethod
from functools import partial
from typing import Callable, cast

from ..core import HandshakeAPIError, SocketClosedAPIError

_LOGGER = logging.getLogger(__name__)

SOCKET_ERRORS = (
    ConnectionResetError,
    asyncio.IncompleteReadError,
    OSError,
    TimeoutError,
)

WRITE_EXCEPTIONS = (RuntimeError, ConnectionResetError, OSError)


class APIFrameHelper(asyncio.Protocol):
    """Helper class to handle the API frame protocol."""

    __slots__ = (
        "_loop",
        "_on_pkt",
        "_on_error",
        "_transport",
        "_writer",
        "_ready_future",
        "_buffer",
        "_buffer_len",
        "_pos",
        "_client_info",
        "_log_name",
        "_debug_enabled",
    )

    def __init__(
        self,
        on_pkt: Callable[[int, bytes], None],
        on_error: Callable[[Exception], None],
        client_info: str,
        log_name: str,
    ) -> None:
        """Initialize the API frame helper."""
        loop = asyncio.get_event_loop()
        self._loop = loop
        self._on_pkt = on_pkt
        self._on_error = on_error
        self._transport: asyncio.Transport | None = None
        self._writer: None | (Callable[[bytes | bytearray | memoryview], None]) = None
        self._ready_future = self._loop.create_future()
        self._buffer: bytes | bytearray | None = None
        self._buffer_len = 0
        self._pos = 0
        self._client_info = client_info
        self._log_name = log_name
        self._debug_enabled = partial(_LOGGER.isEnabledFor, logging.DEBUG)

    def _set_ready_future_exception(self, exc: Exception) -> None:
        if not self._ready_future.done():
            self._ready_future.set_exception(exc)

    def _add_to_buffer(self, data: bytes) -> None:
        """Add data to the buffer."""
        # Ideal case: we have no buffer so we do not need to copy
        if not self._buffer_len:
            self._buffer = data
            self._buffer_len = len(data)
            return

        current_buffer = self._buffer
        # If we are going to mutate the buffer, make sure it is a bytearray
        if type(current_buffer) is bytes:
            current_buffer = bytearray(current_buffer)

        self._buffer = current_buffer + data
        self._buffer_len += len(data)

    def _remove_from_buffer(self) -> None:
        """Remove data from the buffer."""
        end_of_frame_pos = self._pos

        # Ideal case, the buffer is used up, we can just reset it
        if self._buffer_len == end_of_frame_pos:
            self._buffer = None
            self._buffer_len = 0
            return

        current_buffer = self._buffer
        # There is data left in the buffer and its already
        # a bytearray, we can just slice it
        if type(current_buffer) is bytearray:
            del current_buffer[:end_of_frame_pos]

        # Worst case, we need to copy the data to a new buffer
        else:
            self._buffer = bytearray(current_buffer[end_of_frame_pos:])

        self._buffer_len -= end_of_frame_pos

    def _read_exactly(self, length: int) -> bytes | bytearray | None:
        """Read exactly length bytes from the buffer or None if all the bytes are not yet available."""
        original_pos = self._pos
        new_pos = original_pos + length
        if self._buffer_len < new_pos:
            return None
        self._pos = new_pos
        return self._buffer[original_pos:new_pos]

    async def perform_handshake(self, timeout: float) -> None:
        """Perform the handshake with the server."""
        handshake_handle = self._loop.call_later(
            timeout, self._set_ready_future_exception, asyncio.TimeoutError()
        )
        try:
            await self._ready_future
        except asyncio.TimeoutError as err:
            raise HandshakeAPIError(
                f"{self._log_name}: Timeout during handshake"
            ) from err
        finally:
            handshake_handle.cancel()

    @abstractmethod
    def write_packet(self, type_: int, data: bytes) -> None:
        """Write a packet to the socket."""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a new connection."""
        self._transport = cast(asyncio.Transport, transport)
        self._writer = self._transport.write

    def _handle_error_and_close(self, exc: Exception) -> None:
        self._handle_error(exc)
        self.close()

    def _handle_error(self, exc: Exception) -> None:
        self._on_error(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self._handle_error(
            exc or SocketClosedAPIError(f"{self._log_name}: Connection lost")
        )
        return super().connection_lost(exc)

    def eof_received(self) -> bool | None:
        self._handle_error(SocketClosedAPIError(f"{self._log_name}: EOF received"))
        return super().eof_received()

    def close(self) -> None:
        """Close the connection."""
        if self._transport:
            self._transport.close()
            self._transport = None
            self._writer = None
