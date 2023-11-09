from __future__ import annotations

import base64
import logging
from enum import Enum
from functools import partial
from struct import Struct
from typing import TYPE_CHECKING, Any, Callable

from chacha20poly1305_reuseable import ChaCha20Poly1305Reusable
from cryptography.exceptions import InvalidTag
from noise.backends.default import DefaultNoiseBackend  # type: ignore[import-untyped]
from noise.backends.default.ciphers import (  # type: ignore[import-untyped]
    ChaCha20Cipher,
)
from noise.connection import NoiseConnection  # type: ignore[import-untyped]

from ..core import (
    APIConnectionError,
    BadNameAPIError,
    HandshakeAPIError,
    InvalidEncryptionKeyAPIError,
    ProtocolAPIError,
    SocketAPIError,
)
from .base import WRITE_EXCEPTIONS, APIFrameHelper

_LOGGER = logging.getLogger(__name__)


PACK_NONCE = partial(Struct("<LQ").pack, 0)


class ChaCha20CipherReuseable(ChaCha20Cipher):  # type: ignore[misc]
    """ChaCha20 cipher that can be reused."""

    format_nonce = PACK_NONCE

    @property
    def klass(self) -> type[ChaCha20Poly1305Reusable]:
        return ChaCha20Poly1305Reusable


class ESPHomeNoiseBackend(DefaultNoiseBackend):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ciphers["ChaChaPoly"] = ChaCha20CipherReuseable


ESPHOME_NOISE_BACKEND = ESPHomeNoiseBackend()


class NoiseConnectionState(Enum):
    """Noise connection state."""

    HELLO = 1
    HANDSHAKE = 2
    READY = 3
    CLOSED = 4


NOISE_HELLO = b"\x01\x00\x00"

int_ = int


class APINoiseFrameHelper(APIFrameHelper):
    """Frame helper for noise encrypted connections."""

    __slots__ = (
        "_noise_psk",
        "_expected_name",
        "_state",
        "_dispatch",
        "_server_name",
        "_proto",
        "_decrypt",
        "_encrypt",
        "_is_ready",
    )

    def __init__(
        self,
        on_pkt: Callable[[int, bytes], None],
        on_error: Callable[[Exception], None],
        noise_psk: str,
        expected_name: str | None,
        client_info: str,
        log_name: str,
    ) -> None:
        """Initialize the API frame helper."""
        super().__init__(on_pkt, on_error, client_info, log_name)
        self._noise_psk = noise_psk
        self._expected_name = expected_name
        self._set_state(NoiseConnectionState.HELLO)
        self._server_name: str | None = None
        self._decrypt: Callable[[bytes], bytes] | None = None
        self._encrypt: Callable[[bytes], bytes] | None = None
        self._setup_proto()
        self._is_ready = False

    def _set_state(self, state: NoiseConnectionState) -> None:
        """Set the current state."""
        self._state = state
        self._is_ready = state == NoiseConnectionState.READY
        self._dispatch = self.STATE_TO_CALLABLE[state]

    def close(self) -> None:
        """Close the connection."""
        # Make sure we set the ready event if its not already set
        # so that we don't block forever on the ready event if we
        # are waiting for the handshake to complete.
        self._set_ready_future_exception(
            APIConnectionError(f"{self._log_name}: Connection closed")
        )
        self._set_state(NoiseConnectionState.CLOSED)
        super().close()

    def _handle_error_and_close(self, exc: Exception) -> None:
        self._set_ready_future_exception(exc)
        super()._handle_error_and_close(exc)

    def _handle_error(self, exc: Exception) -> None:
        """Handle an error, and provide a good message when during hello."""
        if (
            isinstance(exc, ConnectionResetError)
            and self._state == NoiseConnectionState.HELLO
        ):
            original_exc = exc
            exc = HandshakeAPIError(
                f"{self._log_name}: The connection dropped immediately after encrypted hello; "
                "Try enabling encryption on the device or turning off "
                f"encryption on the client ({self._client_info})."
            )
            exc.__cause__ = original_exc
        super()._handle_error(exc)

    async def perform_handshake(self, timeout: float) -> None:
        """Perform the handshake with the server."""
        self._send_hello_handshake()
        await super().perform_handshake(timeout)

    def data_received(self, data: bytes) -> None:
        self._add_to_buffer(data)
        while self._buffer:
            self._pos = 0
            if (header := self._read_exactly(3)) is None:
                return
            preamble = header[0]
            msg_size_high = header[1]
            msg_size_low = header[2]
            if preamble != 0x01:
                self._handle_error_and_close(
                    ProtocolAPIError(
                        f"{self._log_name}: Marker byte invalid: {header[0]}"
                    )
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
                self._dispatch(self, frame)
            except Exception as err:  # pylint: disable=broad-except
                self._handle_error_and_close(err)
            finally:
                self._remove_from_buffer()

    def _send_hello_handshake(self) -> None:
        """Send a ClientHello to the server."""
        if TYPE_CHECKING:
            assert self._writer is not None, "Writer is not set"

        handshake_frame = b"\x00" + self._proto.write_message()
        frame_len = len(handshake_frame)
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        hello_handshake = NOISE_HELLO + header + handshake_frame

        if self._debug_enabled():
            _LOGGER.debug(
                "%s: Sending encrypted hello handshake: [%s]",
                self._log_name,
                hello_handshake.hex(),
            )

        try:
            self._writer(hello_handshake)
        except WRITE_EXCEPTIONS as err:
            raise SocketAPIError(
                f"{self._log_name}: Error while writing data: {err}"
            ) from err

    def _handle_hello(self, server_hello: bytes) -> None:
        """Perform the handshake with the server."""
        if not server_hello:
            self._handle_error_and_close(
                HandshakeAPIError(f"{self._log_name}: ServerHello is empty")
            )
            return

        # First byte of server hello is the protocol the server chose
        # for this session. Currently only 0x01 (Noise_NNpsk0_25519_ChaChaPoly_SHA256)
        # exists.
        chosen_proto = server_hello[0]
        if chosen_proto != 0x01:
            self._handle_error_and_close(
                HandshakeAPIError(
                    f"{self._log_name}: Unknown protocol selected by client {chosen_proto}"
                )
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
                        f"{self._log_name}: Server sent a different name '{server_name}'",
                        server_name,
                    )
                )
                return

        self._set_state(NoiseConnectionState.HANDSHAKE)

    def _decode_noise_psk(self) -> bytes:
        """Decode the given noise psk from base64 format to raw bytes."""
        psk = self._noise_psk
        server_name = self._server_name
        try:
            psk_bytes = base64.b64decode(psk)
        except ValueError:
            raise InvalidEncryptionKeyAPIError(
                f"{self._log_name}: Malformed PSK {psk}, expected "
                "base64-encoded value",
                server_name,
            )
        if len(psk_bytes) != 32:
            raise InvalidEncryptionKeyAPIError(
                f"{self._log_name}:Malformed PSK {psk}, expected"
                f" 32-bytes of base64 data",
                server_name,
            )
        return psk_bytes

    def _setup_proto(self) -> None:
        """Set up the noise protocol."""
        proto = NoiseConnection.from_name(
            b"Noise_NNpsk0_25519_ChaChaPoly_SHA256", backend=ESPHOME_NOISE_BACKEND
        )
        proto.set_as_initiator()
        proto.set_psks(self._decode_noise_psk())
        proto.set_prologue(b"NoiseAPIInit\x00\x00")
        proto.start_handshake()
        self._proto = proto

    def _handle_handshake(self, msg: bytes) -> None:
        _LOGGER.debug("Starting handshake...")
        if msg[0] != 0:
            explanation = msg[1:].decode()
            if explanation == "Handshake MAC failure":
                self._handle_error_and_close(
                    InvalidEncryptionKeyAPIError(
                        f"{self._log_name}: Invalid encryption key", self._server_name
                    )
                )
                return
            self._handle_error_and_close(
                HandshakeAPIError(f"{self._log_name}: Handshake failure: {explanation}")
            )
            return
        try:
            self._proto.read_message(msg[1:])
        except InvalidTag as invalid_tag_exc:
            ex = InvalidEncryptionKeyAPIError(
                f"{self._log_name}: Invalid encryption key", self._server_name
            )
            ex.__cause__ = invalid_tag_exc
            self._handle_error_and_close(ex)
            return
        _LOGGER.debug("Handshake complete")
        self._set_state(NoiseConnectionState.READY)
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

    def write_packet(self, type_: int_, data: bytes) -> None:
        """Write a packet to the socket."""
        if not self._is_ready:
            raise HandshakeAPIError(f"{self._log_name}: Noise connection is not ready")

        if TYPE_CHECKING:
            assert self._encrypt is not None, "Handshake should be complete"
            assert self._writer is not None, "Writer is not set"

        data_len = len(data)
        data_header = bytes(
            ((type_ >> 8) & 0xFF, type_ & 0xFF, (data_len >> 8) & 0xFF, data_len & 0xFF)
        )
        frame = self._encrypt(data_header + data)

        if self._debug_enabled():
            _LOGGER.debug("%s: Sending frame: [%s]", self._log_name, frame.hex())

        frame_len = len(frame)
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        try:
            self._writer(header + frame)
        except WRITE_EXCEPTIONS as err:
            raise SocketAPIError(
                f"{self._log_name}: Error while writing data: {err}"
            ) from err

    def _handle_frame(self, frame: bytes) -> None:
        """Handle an incoming frame."""
        if TYPE_CHECKING:
            assert self._decrypt is not None, "Handshake should be complete"
        try:
            msg = self._decrypt(frame)
        except InvalidTag as ex:
            self._handle_error_and_close(
                ProtocolAPIError(f"{self._log_name}: Bad encryption frame: {ex!r}")
            )
            return
        # Message layout is
        # 2 bytes: message type
        # 2 bytes: message length
        # N bytes: message data
        type_high = msg[0]
        type_low = msg[1]
        self._on_pkt((type_high << 8) | type_low, msg[4:])

    def _handle_closed(self, frame: bytes) -> None:  # pylint: disable=unused-argument
        """Handle a closed frame."""
        self._handle_error(ProtocolAPIError(f"{self._log_name}: Connection closed"))

    STATE_TO_CALLABLE = {
        NoiseConnectionState.HELLO: _handle_hello,
        NoiseConnectionState.HANDSHAKE: _handle_handshake,
        NoiseConnectionState.READY: _handle_frame,
        NoiseConnectionState.CLOSED: _handle_closed,
    }
