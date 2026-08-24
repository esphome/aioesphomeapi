from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from noise.connection import NoiseConnection

from .._sanitize import MAX_EXPLANATION_LEN, MAX_MAC_LEN, MAX_NAME_LEN, safe_label_str
from ..core import (
    APIConnectionError,
    BadMACAddressAPIError,
    BadNameAPIError,
    EncryptionErrorAPIError,
    EncryptionHelloAPIError,
    EncryptionPlaintextAPIError,
    HandshakeAPIError,
    InvalidEncryptionKeyAPIError,
    ProtocolAPIError,
    ResumeAPIError,
)
from .base import _LOGGER, APIFrameHelper
from .noise_encryption import (
    ESPHOME_NOISE_BACKEND,
    NOISE_PROTOCOL_NAME,
    DecryptCipher,
    EncryptCipher,
    decode_noise_psk,
)
from .noise_resume import (
    build_client_hello,
    build_resume_offer,
    derive_resume_keys,
    parse_resume_accept,
    verify_confirm_mac,
)

if TYPE_CHECKING:
    import asyncio

    from ..connection import APIConnection
    from .packets import Packet


# This is effectively an enum but we don't want to use an enum
# because we have a simple dispatch in the data_received method
# that would be more complicated with an enum and we want to add
# cdefs for each different state so we have a good test for each
# state receiving data since we found that the protractor event
# loop will send use a bytearray instead of bytes was not handled
# correctly.
NOISE_STATE_HELLO = 1
NOISE_STATE_HANDSHAKE = 2
NOISE_STATE_READY = 3
NOISE_STATE_CLOSED = 4


int_ = int

# Cython resolves _MAX_* via cimport from .base and safe_label_str via cimport
# from .._sanitize (noise.pxd); these assignments are the pure-Python
# (SKIP_CYTHON=1) fallback so callers below have a name to resolve.
_MAX_NAME_LEN = MAX_NAME_LEN
_MAX_MAC_LEN = MAX_MAC_LEN
_MAX_EXPLANATION_LEN = MAX_EXPLANATION_LEN


def make_noise_packets(
    packets: list[Packet], encrypt_cipher: EncryptCipher
) -> list[bytes]:
    """Make a list of noise packet."""
    out: list[bytes] = []
    for packet in packets:
        type_ = packet[0]
        data = packet[1]
        data_len = len(data)
        data_header = bytes(
            (
                (type_ >> 8) & 0xFF,
                type_ & 0xFF,
                (data_len >> 8) & 0xFF,
                data_len & 0xFF,
            )
        )
        frame = encrypt_cipher.encrypt(data_header + data)
        frame_len = len(frame)
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        out.append(header)
        out.append(frame)
    return out


class APINoiseFrameHelper(APIFrameHelper):
    """Frame helper for noise encrypted connections."""

    __slots__ = (
        "_decrypt_cipher",
        "_encrypt_cipher",
        "_expected_mac",
        "_expected_name",
        "_hello",
        "_noise_psk",
        "_prologue",
        "_proto",
        "_resume_nonce",
        "_resume_secret",
        "_server_mac",
        "_server_name",
        "_state",
    )

    def __init__(
        self,
        connection: APIConnection,
        noise_psk: str,
        expected_name: str | None,
        expected_mac: str | None,
        client_info: str,
        log_name: str,
        resume_ticket: tuple[bytes, bytes] | None = None,
    ) -> None:
        """Initialize the API frame helper."""
        super().__init__(connection, client_info, log_name)
        self._noise_psk = noise_psk
        self._expected_mac = expected_mac
        self._expected_name = expected_name
        self._state = NOISE_STATE_HELLO
        self._server_name: str | None = None
        self._server_mac: str | None = None
        self._encrypt_cipher: EncryptCipher | None = None
        self._decrypt_cipher: DecryptCipher | None = None
        # Abandoned (set to None) when a resume accept replaces the handshake
        self._proto: NoiseConnection | None = None
        # The offer rides in the prologue-mixed ClientHello body, so old
        # firmware that ignores it still completes a full handshake.
        self._resume_secret: bytes | None = None
        self._resume_nonce: bytes | None = None
        offer = b""
        if resume_ticket is not None:
            session_id, secret = resume_ticket
            offer, self._resume_nonce = build_resume_offer(session_id, secret)
            self._resume_secret = secret
        self._hello, self._prologue = build_client_hello(offer)
        self._setup_proto()

    def close(self) -> None:
        """Close the connection."""
        # Make sure we set the ready event if its not already set
        # so that we don't block forever on the ready event if we
        # are waiting for the handshake to complete.
        self._set_ready_future_exception(
            APIConnectionError(f"{self._log_name}: Connection closed")
        )
        self._state = NOISE_STATE_CLOSED
        super().close()

    def _handle_error(self, exc: Exception) -> None:
        """Handle an error, and provide a good message when during hello."""
        if self._state == NOISE_STATE_HELLO and isinstance(exc, ConnectionResetError):
            original_exc: Exception = exc
            exc = EncryptionHelloAPIError(
                f"{self._log_name}: The connection dropped immediately after encrypted hello; "
                "Try enabling encryption on the device or turning off "
                f"encryption on the client ({self._client_info})"
            )
            exc.__cause__ = original_exc
        super()._handle_error(exc)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a new connection."""
        super().connection_made(transport)
        self._send_hello_handshake()

    def data_received(self, data: bytes | bytearray | memoryview) -> None:
        self._add_to_buffer(data)
        # Message header is 3 bytes
        while self._buffer_len >= 3:
            if TYPE_CHECKING:
                assert self._buffer is not None, "Buffer should be set"
            self._pos = 3
            header = self._buffer
            preamble = header[0]
            if preamble != 0x01:
                if preamble == 0x00:
                    self._handle_error_and_close(
                        EncryptionPlaintextAPIError(
                            f"{self._log_name}: The device is using plaintext protocol; "
                            "Try enabling encryption on the device or turning off "
                            f"encryption on the client ({self._client_info})"
                        )
                    )
                else:
                    self._handle_error_and_close(
                        ProtocolAPIError(
                            f"{self._log_name}: Marker byte invalid: {preamble}"
                        )
                    )
                return
            if (frame := self._read((header[1] << 8) | header[2])) is None:
                # The complete frame is not yet available, wait for more data
                # to arrive before continuing, since callback_packet has not
                # been called yet the buffer will not be cleared and the next
                # call to data_received will continue processing the packet
                # at the start of the frame.
                return

            # asyncio already runs data_received in a try block
            # which will call connection_lost if an exception is raised
            if self._state == NOISE_STATE_READY:
                self._handle_frame(frame)
            elif self._state == NOISE_STATE_HELLO:
                self._handle_hello(frame)
            elif self._state == NOISE_STATE_HANDSHAKE:
                self._handle_handshake(frame)
            else:
                self._handle_closed(frame)

            self._remove_from_buffer()

    def _send_hello_handshake(self) -> None:
        """Send a ClientHello to the server."""
        if self._resume_secret is not None:
            # Offering resume: message 1 is only needed if the device
            # declines, so wait for the ServerHello instead of pipelining
            self._write_bytes((self._hello,), _LOGGER.isEnabledFor(logging.DEBUG))
            return
        self._write_bytes(
            (self._hello, *self._handshake_message()),
            _LOGGER.isEnabledFor(logging.DEBUG),
        )

    def _handshake_message(self) -> tuple[bytes, bytes, bytes]:
        """Frame handshake message 1: header, status byte, noise message."""
        if TYPE_CHECKING:
            assert self._proto is not None
        handshake_frame = self._proto.write_message()
        frame_len = len(handshake_frame) + 1
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        return header, b"\x00", bytes(handshake_frame)

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
            # server name found, this extension was added in 2022.2.
            # Compare against the raw decoded value so a peer can't sneak
            # past expected_name by appending non-printable bytes that the
            # sanitizer would strip; only the value used for logs and for
            # later self-storage gets sanitized + length-capped.
            server_name_raw = server_hello[1:server_name_i].decode("utf-8", "replace")
            server_name = safe_label_str(server_name_raw, _MAX_NAME_LEN)
            self._server_name = server_name

            if (
                self._expected_name is not None
                and self._expected_name != server_name_raw
            ):
                self._handle_error_and_close(
                    BadNameAPIError(
                        f"{self._log_name}: Server sent a different name '{server_name}'",
                        server_name,
                    )
                )
                return

            mac_address_i = server_hello.find(b"\0", server_name_i + 1)
            if mac_address_i != -1:
                # mac address found, this extension was added in 2025.4.
                # Same raw-vs-sanitized split as the name field above.
                mac_address_raw = server_hello[
                    server_name_i + 1 : mac_address_i
                ].decode("utf-8", "replace")
                mac_address = safe_label_str(mac_address_raw, _MAX_MAC_LEN)
                self._server_mac = mac_address
                if (
                    self._expected_mac is not None
                    and self._expected_mac != mac_address_raw
                ):
                    self._handle_error_and_close(
                        BadMACAddressAPIError(
                            f"{self._log_name}: Server sent a different mac '{mac_address}'",
                            server_name,
                            mac_address,
                        )
                    )
                    return

                if self._resume_secret is not None:
                    self._handle_resume_accept(server_hello[mac_address_i + 1 :])
                    if self._state != NOISE_STATE_HELLO:
                        # Resumed (READY) or failed verification (CLOSED)
                        return

        if self._resume_secret is not None:
            # The device declined the resume offer; send the deferred message 1
            self._write_bytes(
                self._handshake_message(), _LOGGER.isEnabledFor(logging.DEBUG)
            )
        self._state = NOISE_STATE_HANDSHAKE

    def _handle_resume_accept(self, ext: bytes) -> None:
        """Handle a resume accept trailing the ServerHello.

        State stays HELLO when no accept is present, READY on a verified
        accept, CLOSED when verification fails.
        """
        if (parsed := parse_resume_accept(ext)) is None:
            # Old firmware (no trailing bytes) or unknown extension: the
            # device is doing a full handshake
            return
        server_nonce, confirm_mac = parsed
        if TYPE_CHECKING:
            assert self._resume_secret is not None
            assert self._resume_nonce is not None
        if not verify_confirm_mac(
            self._resume_secret, self._resume_nonce, server_nonce, confirm_mac
        ):
            self._handle_error_and_close(
                ResumeAPIError(f"{self._log_name}: Resume accept failed verification")
            )
            return
        k_c2d, k_d2c = derive_resume_keys(
            self._resume_secret, self._resume_nonce, server_nonce, self._prologue
        )
        # The full handshake the client started is abandoned; free it
        self._proto = None
        _LOGGER.debug("%s: Session resumed", self._log_name)
        self._become_ready(EncryptCipher.from_key(k_c2d), DecryptCipher.from_key(k_d2c))

    def _decode_noise_psk(self) -> bytes:
        """Decode the given noise psk from base64 format to raw bytes."""
        try:
            return decode_noise_psk(self._noise_psk)
        except ValueError as err:
            msg = f"{self._log_name}: {err}"
            raise InvalidEncryptionKeyAPIError(
                msg,
                self._server_name,
                self._server_mac,
            ) from err

    def _setup_proto(self) -> None:
        """Set up the noise protocol.

        Mirrors aioesphomeapi.noise.NoiseHandshake rather than delegating to
        it: this module is cythonized and its hot path and .pxd stay
        untouched. Keep the two in sync.
        """
        proto = NoiseConnection.from_name(
            NOISE_PROTOCOL_NAME, backend=ESPHOME_NOISE_BACKEND
        )
        proto.set_as_initiator()
        proto.set_psks(self._decode_noise_psk())
        # "NoiseAPIInit" + big-endian length of the ClientHello body + the
        # body itself; the device mixes whatever ClientHello it receives, so
        # the two sides always agree.
        proto.set_prologue(self._prologue)
        proto.start_handshake()
        self._proto = proto

    def _error_on_incorrect_preamble(self, msg: bytes) -> None:
        """Handle an incorrect preamble."""
        # Compare against the raw decoded value so a peer can't get itself
        # mis-classified as InvalidEncryptionKeyAPIError by appending
        # non-printable bytes to the canonical "Handshake MAC failure" string;
        # only the text included in the error message gets sanitized.
        explanation_raw = msg[1:].decode("utf-8", "replace")
        explanation = safe_label_str(explanation_raw, _MAX_EXPLANATION_LEN)
        if explanation_raw != "Handshake MAC failure":
            exc = HandshakeAPIError(
                f"{self._log_name}: Handshake failure: {explanation}"
            )
        elif self._resume_secret is not None:
            # A resume offer was in the prologue, so a MAC failure is
            # ambiguous: wrong key, or a prologue mismatch caused by the
            # offer. The ticket is already spent; retry once with a bare
            # ClientHello before reporting a key problem to the user.
            exc = ResumeAPIError(
                f"{self._log_name}: Handshake MAC failure after resume offer"
            )
        else:
            exc = InvalidEncryptionKeyAPIError(
                f"{self._log_name}: Invalid encryption key",
                self._server_name,
                self._server_mac,
            )
        self._handle_error_and_close(exc)

    def _handle_handshake(self, msg: bytes) -> None:
        if not msg:
            self._handle_error_and_close(
                HandshakeAPIError(f"{self._log_name}: Handshake frame is empty")
            )
            return
        if msg[0] != 0:
            self._error_on_incorrect_preamble(msg)
            return
        if TYPE_CHECKING:
            assert self._proto is not None
        try:
            self._proto.read_message(msg[1:])
        except InvalidTag as exc:
            # The peer's handshake response failed AEAD authentication. Either
            # the PSK doesn't match or the ciphertext was tampered with. ESPHome
            # firmware normally rejects with the dedicated preamble=0x01
            # "Handshake MAC failure" frame, so reaching this path means the
            # peer is buggy or hostile; surface the same friendly error the
            # named-failure branch raises.
            key_err = InvalidEncryptionKeyAPIError(
                f"{self._log_name}: Invalid encryption key",
                self._server_name,
                self._server_mac,
            )
            key_err.__cause__ = exc
            self._handle_error_and_close(key_err)
            return
        except Exception as exc:  # noqa: BLE001
            handshake_err = HandshakeAPIError(
                f"{self._log_name}: Handshake failed: {exc}"
            )
            handshake_err.__cause__ = exc
            self._handle_error_and_close(handshake_err)
            return
        if TYPE_CHECKING:
            assert self._proto is not None
        noise_protocol = self._proto.noise_protocol
        self._become_ready(
            EncryptCipher(noise_protocol.cipher_state_encrypt),  # pylint: disable=no-member
            DecryptCipher(noise_protocol.cipher_state_decrypt),  # pylint: disable=no-member
        )

    def _become_ready(
        self, encrypt_cipher: EncryptCipher, decrypt_cipher: DecryptCipher
    ) -> None:
        """Install the transport ciphers and release handshake-only state."""
        self._encrypt_cipher = encrypt_cipher
        self._decrypt_cipher = decrypt_cipher
        self._resume_secret = None
        self._resume_nonce = None
        self._state = NOISE_STATE_READY
        self.ready_future.set_result(None)

    def write_packets(self, packets: list[Packet], debug_enabled: bool) -> None:
        """Write a packets to the socket.

        Packets are in the format of tuple[protobuf_type, protobuf_data]
        """
        if TYPE_CHECKING:
            assert self._encrypt_cipher is not None, "Handshake should be complete"
        self._write_bytes(
            make_noise_packets(packets, self._encrypt_cipher), debug_enabled
        )

    def _handle_frame(self, frame: bytes) -> None:
        """Handle an incoming frame."""
        if TYPE_CHECKING:
            assert self._decrypt_cipher is not None, "Handshake should be complete"
        try:
            msg = self._decrypt_cipher.decrypt(frame)
        except InvalidTag:
            # This shouldn't happen since we already checked the tag during handshake
            # but it could happen if the server sends a bad frame see
            # issue https://github.com/esphome/aioesphomeapi/issues/1044
            self._handle_error_and_close(
                EncryptionErrorAPIError(
                    f"{self._log_name}: Encryption error", self._server_name
                )
            )
            return
        msg_length = len(msg)
        msg_cstr = msg
        if msg_length < 4:
            # Important: we must bound check msg_length to ensure we
            # do not read past the end of the message in the payload
            # slicing below
            self._handle_error_and_close(
                ProtocolAPIError(
                    f"{self._log_name}: Decrypted message too short: {msg_length} bytes"
                )
            )
            return
        # Message layout is
        # 2 bytes: message type   (0:type_high,   1:type_low)
        # 2 bytes: message length (2:length_high, 3:length_low)
        # - We ignore the message length field because we do not
        #   trust the remote end to send the correct length
        # N bytes: message data   (4:...)
        msg_type = (msg_cstr[0] << 8) | msg_cstr[1]
        # Important: we must explicitly use msg_length here since msg_cstr
        # is a cstring and Cython will stop at the first null byte if we
        # do not use msg_length
        payload = msg_cstr[4:msg_length]
        self._connection.process_packet(msg_type, payload)

    def _handle_closed(self, frame: bytes) -> None:  # noqa: ARG002 # pylint: disable=unused-argument
        """Handle a closed frame."""
        self._handle_error(ProtocolAPIError(f"{self._log_name}: Connection closed"))
