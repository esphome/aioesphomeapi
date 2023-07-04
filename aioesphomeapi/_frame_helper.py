import asyncio
import base64
import logging
from abc import abstractmethod
from enum import Enum
from functools import partial
from typing import TYPE_CHECKING, Any, Callable, Optional, Union, cast

import async_timeout
from chacha20poly1305_reuseable import ChaCha20Poly1305Reusable
from cryptography.exceptions import InvalidTag
from noise.backends.default import DefaultNoiseBackend  # type: ignore[import]
from noise.backends.default.ciphers import ChaCha20Cipher  # type: ignore[import]
from noise.connection import NoiseConnection  # type: ignore[import]

from .core import (
    APIConnectionError,
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


class ChaCha20CipherReuseable(ChaCha20Cipher):  # type: ignore[misc]
    @property
    def klass(self):  # type: ignore[no-untyped-def]
        return ChaCha20Poly1305Reusable


class ESPHomeNoiseBackend(DefaultNoiseBackend):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ciphers["ChaChaPoly"] = ChaCha20CipherReuseable


ESPHOME_NOISE_BACKEND = ESPHomeNoiseBackend()


class APIFrameHelper(asyncio.Protocol):
    """Helper class to handle the API frame protocol."""

    __slots__ = (
        "_on_pkt",
        "_on_error",
        "_transport",
        "_connected_event",
        "_buffer",
        "_pos",
    )

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
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug("Sending plaintext frame %s", data.hex())

        try:
            self._transport.write(data)
        except (RuntimeError, ConnectionResetError, OSError) as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def perform_handshake(self) -> None:
        """Perform the handshake."""
        await self._connected_event.wait()

    def data_received(self, data: bytes) -> None:  # pylint: disable=too-many-branches
        self._buffer += data
        while self._buffer:
            # Read preamble, which should always 0x00
            # Also try to get the length and msg type
            # to avoid multiple calls to _read_exactly
            init_bytes = self._init_read(3)
            if init_bytes is None:
                return
            msg_type_int: Optional[int] = None
            length_int: Optional[int] = None
            preamble, length_high, maybe_msg_type = init_bytes
            if preamble != 0x00:
                if preamble == 0x01:
                    self._handle_error_and_close(
                        RequiresEncryptionAPIError("Connection requires encryption")
                    )
                    return
                self._handle_error_and_close(
                    ProtocolAPIError(f"Invalid preamble {preamble:02x}")
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
                self._callback_packet(msg_type_int, b"")
                # If we have more data, continue processing
                continue

            packet_data = self._read_exactly(length_int)
            # The packet data is not yet available, wait for more data
            # to arrive before continuing, since callback_packet has not
            # been called yet the buffer will not be cleared and the next
            # call to data_received will continue processing the packet
            # at the start of the frame.
            if packet_data is None:
                return

            self._callback_packet(msg_type_int, bytes(packet_data))
            # If we have more data, continue processing


def _decode_noise_psk(psk: str, server_name: Optional[str]) -> bytes:
    """Decode the given noise psk from base64 format to raw bytes."""
    try:
        psk_bytes = base64.b64decode(psk)
    except ValueError:
        raise InvalidEncryptionKeyAPIError(
            f"Malformed PSK {psk}, expected base64-encoded value", server_name
        )
    if len(psk_bytes) != 32:
        raise InvalidEncryptionKeyAPIError(
            f"Malformed PSK {psk}, expected 32-bytes of base64 data", server_name
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

    __slots__ = (
        "_ready_future",
        "_noise_psk",
        "_expected_name",
        "_state",
        "_server_name",
        "_proto",
        "_decrypt",
        "_encrypt",
    )

    def __init__(
        self,
        on_pkt: Callable[[int, bytes], None],
        on_error: Callable[[Exception], None],
        noise_psk: str,
        expected_name: Optional[str],
    ) -> None:
        """Initialize the API frame helper."""
        super().__init__(on_pkt, on_error)
        self._ready_future = asyncio.get_event_loop().create_future()
        self._noise_psk = noise_psk
        self._expected_name = expected_name
        self._state = NoiseConnectionState.HELLO
        self._server_name: Optional[str] = None
        self._decrypt: Optional[Callable[[bytes], bytes]] = None
        self._encrypt: Optional[Callable[[bytes], bytes]] = None
        self._setup_proto()

    def _set_ready_future_exception(self, exc: Exception) -> None:
        if not self._ready_future.done():
            self._ready_future.set_exception(exc)

    def close(self) -> None:
        """Close the connection."""
        # Make sure we set the ready event if its not already set
        # so that we don't block forever on the ready event if we
        # are waiting for the handshake to complete.
        self._set_ready_future_exception(APIConnectionError("Connection closed"))
        self._state = NoiseConnectionState.CLOSED
        super().close()

    def _handle_error_and_close(self, exc: Exception) -> None:
        self._set_ready_future_exception(exc)
        super()._handle_error_and_close(exc)

    def _write_frame(self, frame: bytes) -> None:
        """Write a packet to the socket, the caller should not have the lock.

        The entire packet must be written in a single call to write
        to avoid locking.
        """
        assert self._transport is not None, "Transport is not set"
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug("Sending frame: [%s]", frame.hex())

        frame_len = len(frame)
        try:
            header = bytes(
                [
                    0x01,
                    (frame_len >> 8) & 0xFF,
                    frame_len & 0xFF,
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
                await self._ready_future
        except asyncio.TimeoutError as err:
            raise HandshakeAPIError("Timeout during handshake") from err

    def data_received(self, data: bytes) -> None:
        self._buffer += data
        while self._buffer:
            header = self._init_read(3)
            if header is None:
                return
            preamble, msg_size_high, msg_size_low = header
            if preamble != 0x01:
                self._handle_error_and_close(
                    ProtocolAPIError(f"Marker byte invalid: {header[0]}")
                )
                return
            frame = self._read_exactly((msg_size_high << 8) | msg_size_low)
            # The complete frame is not yet available, wait for more data
            # to arrive before continuing, since callback_packet has not
            # been called yet the buffer will not be cleared and the next
            # call to data_received will continue processing the packet
            # at the start of the frame.
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
            self._handle_error_and_close(HandshakeAPIError("ServerHello is empty"))
            return

        # First byte of server hello is the protocol the server chose
        # for this session. Currently only 0x01 (Noise_NNpsk0_25519_ChaChaPoly_SHA256)
        # exists.
        chosen_proto = server_hello[0]
        if chosen_proto != 0x01:
            self._handle_error_and_close(
                HandshakeAPIError(f"Unknown protocol selected by client {chosen_proto}")
            )
            return

        # Check name matches expected name (for noise sessions, this is done
        # during hello phase before a connection is set up)
        # Server name is encoded as a string followed by a zero byte after the chosen proto byte
        server_name_i = server_hello.find(b"\0", 1)
        if server_name_i != -1:
            # server name found, this extension was added in 2022.2
            server_name = server_hello[1:server_name_i].decode()
            self._server_name = server_name

            if self._expected_name is not None and self._expected_name != server_name:
                self._handle_error_and_close(
                    BadNameAPIError(
                        f"Server sent a different name '{server_name}'", server_name
                    )
                )
                return

        self._state = NoiseConnectionState.HANDSHAKE
        self._send_handshake()

    def _setup_proto(self) -> None:
        """Set up the noise protocol."""
        self._proto = NoiseConnection.from_name(
            b"Noise_NNpsk0_25519_ChaChaPoly_SHA256", backend=ESPHOME_NOISE_BACKEND
        )
        self._proto.set_as_initiator()
        self._proto.set_psks(_decode_noise_psk(self._noise_psk, self._server_name))
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
                self._handle_error_and_close(
                    InvalidEncryptionKeyAPIError(
                        "Invalid encryption key", self._server_name
                    )
                )
                return
            self._handle_error_and_close(
                HandshakeAPIError(f"Handshake failure: {explanation}")
            )
            return
        try:
            self._proto.read_message(msg[1:])
        except InvalidTag as invalid_tag_exc:
            ex = InvalidEncryptionKeyAPIError(
                "Invalid encryption key", self._server_name
            )
            ex.__cause__ = invalid_tag_exc
            self._handle_error_and_close(ex)
            return
        _LOGGER.debug("Handshake complete")
        self._state = NoiseConnectionState.READY
        noise_protocol = self._proto.noise_protocol
        self._decrypt = partial(
            noise_protocol.cipher_state_decrypt.decrypt_with_ad,  # pylint: disable=no-member
            None,
        )
        self._encrypt = partial(
            noise_protocol.cipher_state_encrypt.encrypt_with_ad,  # pylint: disable=no-member
            None,
        )
        self._ready_future.set_result(None)

    def write_packet(self, type_: int, data: bytes) -> None:
        """Write a packet to the socket."""
        if self._state != NoiseConnectionState.READY:
            raise HandshakeAPIError("Noise connection is not ready")
        if TYPE_CHECKING:
            assert self._encrypt is not None, "Handshake should be complete"
        data_len = len(data)
        self._write_frame(
            self._encrypt(
                bytes(
                    [
                        (type_ >> 8) & 0xFF,
                        (type_ >> 0) & 0xFF,
                        (data_len >> 8) & 0xFF,
                        (data_len >> 0) & 0xFF,
                    ]
                )
                + data
            )
        )

    def _handle_frame(self, frame: bytearray) -> None:
        """Handle an incoming frame."""
        if TYPE_CHECKING:
            assert self._decrypt is not None, "Handshake should be complete"
        try:
            msg = self._decrypt(bytes(frame))
        except InvalidTag as ex:
            self._handle_error_and_close(
                ProtocolAPIError(f"Bad encryption frame: {ex!r}")
            )
            return
        msg_len = len(msg)
        if msg_len < 4:
            self._handle_error_and_close(ProtocolAPIError(f"Bad packet frame: {msg!r}"))
            return
        msg_type_high, msg_type_low, data_len_high, data_len_low = msg[:4]
        msg_type = (msg_type_high << 8) | msg_type_low
        data_len = (data_len_high << 8) | data_len_low
        if data_len + 4 != msg_len:
            self._handle_error_and_close(
                ProtocolAPIError(f"Bad data len: {data_len} vs {msg_len}")
            )
            return
        self._on_pkt(msg_type, msg[4:])

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
