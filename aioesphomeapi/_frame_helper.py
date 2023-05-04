import asyncio
import base64
import logging
from abc import abstractmethod
from enum import Enum
from typing import Callable, Optional, Union, cast

import async_timeout
from noise.connection import NoiseConnection  # type: ignore

from .core import (
    BadNameAPIError,
    HandshakeAPIError,
    InvalidEncryptionKeyAPIError,
    ProtocolAPIError,
    RequiresEncryptionAPIError,
    SocketAPIError,
    SocketClosedAPIError,
)
from .util import bytes_to_varuint, varuint_to_bytes

_LOGGER = logging.getLogger(__name__)

SOCKET_ERRORS = (
    ConnectionResetError,
    asyncio.IncompleteReadError,
    OSError,
    TimeoutError,
)


class APIFrameHelper(asyncio.Protocol):
    """Helper class to handle the API frame protocol."""

    def __init__(
        self,
        on_pkt: Callable[[int, bytes], None],
        on_error: Callable[[Exception], None],
    ) -> None:
        """Initialize the API frame helper."""
        self._on_pkt = on_pkt
        self._on_error = on_error
        self._transport: Optional[asyncio.Transport] = None
        self._connected_event = asyncio.Event()
        self._buffer = bytearray()
        self._pos = 0

    def _init_read(self, length: int) -> Optional[bytearray]:
        """Start reading a packet from the buffer."""
        self._pos = 0
        return self._read_exactly(length)

    def _read_exactly(self, length: int) -> Optional[bytearray]:
        """Read exactly length bytes from the buffer or None if all the bytes are not yet available."""
        original_pos = self._pos
        new_pos = original_pos + length
        if len(self._buffer) < new_pos:
            return None
        self._pos = new_pos
        return self._buffer[original_pos:new_pos]

    @abstractmethod
    async def perform_handshake(self) -> None:
        """Perform the handshake."""

    @abstractmethod
    def write_packet(self, type_: int, data: bytes) -> None:
        """Write a packet to the socket."""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a new connection."""
        self._transport = cast(asyncio.Transport, transport)
        self._connected_event.set()

    def _handle_error_and_close(self, exc: Exception) -> None:
        self._handle_error(exc)
        self.close()

    def _handle_error(self, exc: Exception) -> None:
        self._on_error(exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._handle_error(exc or SocketClosedAPIError("Connection lost"))
        return super().connection_lost(exc)

    def eof_received(self) -> Optional[bool]:
        self._handle_error(SocketClosedAPIError("EOF received"))
        return super().eof_received()

    def close(self) -> None:
        """Close the connection."""
        if self._transport:
            self._transport.close()


class APIPlaintextFrameHelper(APIFrameHelper):
    """Frame helper for plaintext API connections."""

    def _callback_packet(self, type_: int, data: Union[bytes, bytearray]) -> None:
        """Complete reading a packet from the buffer."""
        del self._buffer[: self._pos]
        self._on_pkt(type_, data)

    def write_packet(self, type_: int, data: bytes) -> None:
        """Write a packet to the socket, the caller should not have the lock.

        The entire packet must be written in a single call to write
        to avoid locking.
        """
        assert self._transport is not None, "Transport should be set"
        data = b"\0" + varuint_to_bytes(len(data)) + varuint_to_bytes(type_) + data
        _LOGGER.debug("Sending plaintext frame %s", data.hex())

        try:
            self._transport.write(data)
        except (RuntimeError, ConnectionResetError, OSError) as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def perform_handshake(self) -> None:
        """Perform the handshake."""
        await self._connected_event.wait()

    def data_received(self, data: bytes) -> None:
        self._buffer += data
        while len(self._buffer) >= 3:
            # Read preamble, which should always 0x00
            # Also try to get the length and msg type
            # to avoid multiple calls to readexactly
            init_bytes = self._init_read(3)
            assert init_bytes is not None, "Buffer should have at least 3 bytes"
            if init_bytes[0] != 0x00:
                if init_bytes[0] == 0x01:
                    self._handle_error_and_close(
                        RequiresEncryptionAPIError("Connection requires encryption")
                    )
                    return
                self._handle_error_and_close(
                    ProtocolAPIError(f"Invalid preamble {init_bytes[0]:02x}")
                )
                return

            if init_bytes[1] & 0x80 == 0x80:
                # Length is longer than 1 byte
                length = init_bytes[1:3]
                msg_type = b""
            else:
                # This is the most common case with 99% of messages
                # needing a single byte for length and type which means
                # we avoid 2 calls to readexactly
                length = init_bytes[1:2]
                msg_type = init_bytes[2:3]

            # If the message is long, we need to read the rest of the length
            while length[-1] & 0x80 == 0x80:
                add_length = self._read_exactly(1)
                if add_length is None:
                    return
                length += add_length

            # If the message length was longer than 1 byte, we need to read the
            # message type
            while not msg_type or (msg_type[-1] & 0x80) == 0x80:
                add_msg_type = self._read_exactly(1)
                if add_msg_type is None:
                    return
                msg_type += add_msg_type

            length_int = bytes_to_varuint(bytes(length))
            assert length_int is not None
            msg_type_int = bytes_to_varuint(bytes(msg_type))
            assert msg_type_int is not None

            if length_int == 0:
                self._callback_packet(msg_type_int, b"")
                # If we have more data, continue processing
                continue

            packet_data = self._read_exactly(length_int)
            if packet_data is None:
                return

            self._callback_packet(msg_type_int, bytes(packet_data))
            # If we have more data, continue processing


def _decode_noise_psk(psk: str) -> bytes:
    """Decode the given noise psk from base64 format to raw bytes."""
    try:
        psk_bytes = base64.b64decode(psk)
    except ValueError:
        raise InvalidEncryptionKeyAPIError(
            f"Malformed PSK {psk}, expected base64-encoded value"
        )
    if len(psk_bytes) != 32:
        raise InvalidEncryptionKeyAPIError(
            f"Malformed PSK {psk}, expected 32-bytes of base64 data"
        )
    return psk_bytes


class NoiseConnectionState(Enum):
    """Noise connection state."""

    HELLO = 1
    HANDSHAKE = 2
    READY = 3
    CLOSED = 4


class APINoiseFrameHelper(APIFrameHelper):
    """Frame helper for noise encrypted connections."""

    def __init__(
        self,
        on_pkt: Callable[[int, bytes], None],
        on_error: Callable[[Exception], None],
        noise_psk: str,
        expected_name: Optional[str],
    ) -> None:
        """Initialize the API frame helper."""
        super().__init__(on_pkt, on_error)
        self._ready_event = asyncio.Event()
        self._noise_psk = noise_psk
        self._expected_name = expected_name
        self._state = NoiseConnectionState.HELLO
        self._setup_proto()

    def close(self) -> None:
        """Close the connection."""
        # Make sure we set the ready event if its not already set
        # so that we don't block forever on the ready event if we
        # are waiting for the handshake to complete.
        self._ready_event.set()
        self._state = NoiseConnectionState.CLOSED
        super().close()

    def _write_frame(self, frame: bytes) -> None:
        """Write a packet to the socket, the caller should not have the lock.

        The entire packet must be written in a single call to write
        to avoid locking.
        """
        _LOGGER.debug("Sending frame %s", frame.hex())
        assert self._transport is not None, "Transport is not set"

        try:
            header = bytes(
                [
                    0x01,
                    (len(frame) >> 8) & 0xFF,
                    len(frame) & 0xFF,
                ]
            )
            self._transport.write(header + frame)
        except (RuntimeError, ConnectionResetError, OSError) as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def perform_handshake(self) -> None:
        """Perform the handshake with the server."""
        self._send_hello()
        try:
            async with async_timeout.timeout(60.0):
                await self._ready_event.wait()
        except asyncio.TimeoutError as err:
            raise HandshakeAPIError("Timeout during handshake") from err

    def data_received(self, data: bytes) -> None:
        self._buffer += data
        while len(self._buffer) >= 3:
            header = self._init_read(3)
            assert header is not None, "Buffer should have at least 3 bytes"
            if header[0] != 0x01:
                self._handle_error_and_close(
                    ProtocolAPIError(f"Marker byte invalid: {header[0]}")
                )
            msg_size = (header[1] << 8) | header[2]
            frame = self._read_exactly(msg_size)
            if frame is None:
                return

            try:
                self.STATE_TO_CALLABLE[self._state](self, frame)
            except Exception as err:  # pylint: disable=broad-except
                self._handle_error_and_close(err)
            finally:
                del self._buffer[: self._pos]

    def _send_hello(self) -> None:
        """Send a ClientHello to the server."""
        self._write_frame(b"")  # ClientHello

    def _handle_hello(self, server_hello: bytearray) -> None:
        """Perform the handshake with the server, the caller is responsible for having the lock."""
        if not server_hello:
            raise HandshakeAPIError("ServerHello is empty")

        # First byte of server hello is the protocol the server chose
        # for this session. Currently only 0x01 (Noise_NNpsk0_25519_ChaChaPoly_SHA256)
        # exists.
        chosen_proto = server_hello[0]
        if chosen_proto != 0x01:
            raise HandshakeAPIError(
                f"Unknown protocol selected by client {chosen_proto}"
            )

        # Check name matches expected name (for noise sessions, this is done
        # during hello phase before a connection is set up)
        # Server name is encoded as a string followed by a zero byte after the chosen proto byte
        server_name_i = server_hello.find(b"\0", 1)
        if server_name_i != -1:
            # server name found, this extension was added in 2022.2
            server_name = server_hello[1:server_name_i].decode()
            if self._expected_name is not None and self._expected_name != server_name:
                raise BadNameAPIError(
                    f"Server sent a different name '{server_name}'", server_name
                )

        self._state = NoiseConnectionState.HANDSHAKE
        self._send_handshake()

    def _setup_proto(self) -> None:
        """Set up the noise protocol."""
        self._proto = NoiseConnection.from_name(b"Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        self._proto.set_as_initiator()
        self._proto.set_psks(_decode_noise_psk(self._noise_psk))
        self._proto.set_prologue(b"NoiseAPIInit" + b"\x00\x00")
        self._proto.start_handshake()

    def _send_handshake(self) -> None:
        """Send the handshake message."""
        self._write_frame(b"\x00" + self._proto.write_message())

    def _handle_handshake(self, msg: bytearray) -> None:
        _LOGGER.debug("Starting handshake...")
        if msg[0] != 0:
            explanation = msg[1:].decode()
            if explanation == "Handshake MAC failure":
                raise InvalidEncryptionKeyAPIError("Invalid encryption key")
            raise HandshakeAPIError(f"Handshake failure: {explanation}")
        self._proto.read_message(msg[1:])
        _LOGGER.debug("Handshake complete")
        self._state = NoiseConnectionState.READY
        self._ready_event.set()

    def write_packet(self, type_: int, data: bytes) -> None:
        """Write a packet to the socket."""
        if self._state != NoiseConnectionState.READY:
            raise HandshakeAPIError("Noise connection is not ready")
        self._write_frame(
            self._proto.encrypt(
                (
                    bytes(
                        [
                            (type_ >> 8) & 0xFF,
                            (type_ >> 0) & 0xFF,
                            (len(data) >> 8) & 0xFF,
                            (len(data) >> 0) & 0xFF,
                        ]
                    )
                    + data
                )
            )
        )

    def _handle_frame(self, frame: bytearray) -> None:
        """Handle an incoming frame."""
        assert self._proto is not None
        msg = self._proto.decrypt(bytes(frame))
        if len(msg) < 4:
            raise ProtocolAPIError(f"Bad packet frame: {msg}")
        pkt_type = (msg[0] << 8) | msg[1]
        data_len = (msg[2] << 8) | msg[3]
        if data_len + 4 > len(msg):
            raise ProtocolAPIError(f"Bad data len: {data_len} vs {len(msg)}")
        data = msg[4 : 4 + data_len]
        return self._on_pkt(pkt_type, data)

    def _handle_closed(  # pylint: disable=unused-argument
        self, frame: bytearray
    ) -> None:
        """Handle a closed frame."""
        self._handle_error(ProtocolAPIError("Connection closed"))

    STATE_TO_CALLABLE = {
        NoiseConnectionState.HELLO: _handle_hello,
        NoiseConnectionState.HANDSHAKE: _handle_handshake,
        NoiseConnectionState.READY: _handle_frame,
        NoiseConnectionState.CLOSED: _handle_closed,
    }
