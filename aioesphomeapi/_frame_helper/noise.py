from __future__ import annotations

import asyncio
import binascii
import logging
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from noise.connection import NoiseConnection

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
)
from .base import _LOGGER, APIFrameHelper
from .noise_encryption import ESPHOME_NOISE_BACKEND, DecryptCipher, EncryptCipher
from .packets import make_noise_packets

if TYPE_CHECKING:
    from ..connection import APIConnection


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


NOISE_HELLO = b"\x01\x00\x00"

int_ = int


class APINoiseFrameHelper(APIFrameHelper):
    """Frame helper for noise encrypted connections."""

    __slots__ = (
        "_decrypt_cipher",
        "_encrypt_cipher",
        "_expected_mac",
        "_expected_name",
        "_noise_psk",
        "_proto",
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
        handshake_frame = self._proto.write_message()
        frame_len = len(handshake_frame) + 1
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        self._write_bytes(
            (NOISE_HELLO, header, b"\x00", handshake_frame),
            _LOGGER.isEnabledFor(logging.DEBUG),
        )

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

            mac_address_i = server_hello.find(b"\0", server_name_i + 1)
            if mac_address_i != -1:
                # mac address found, this extension was added in 2025.4
                mac_address = server_hello[server_name_i + 1 : mac_address_i].decode()
                self._server_mac = mac_address
                if self._expected_mac is not None and self._expected_mac != mac_address:
                    self._handle_error_and_close(
                        BadMACAddressAPIError(
                            f"{self._log_name}: Server sent a different mac '{mac_address}'",
                            server_name,
                            mac_address,
                        )
                    )
                    return

        self._state = NOISE_STATE_HANDSHAKE

    def _decode_noise_psk(self) -> bytes:
        """Decode the given noise psk from base64 format to raw bytes."""
        psk = self._noise_psk
        server_name = self._server_name
        server_mac = self._server_mac
        try:
            psk_bytes = binascii.a2b_base64(psk)
        except ValueError:
            raise InvalidEncryptionKeyAPIError(
                f"{self._log_name}: Malformed PSK `{psk}`, expected "
                "base64-encoded value",
                server_name,
                server_mac,
            )
        if len(psk_bytes) != 32:
            raise InvalidEncryptionKeyAPIError(
                f"{self._log_name}:Malformed PSK `{psk}`, expected"
                f" 32-bytes of base64 data",
                server_name,
                server_mac,
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

    def _error_on_incorrect_preamble(self, msg: bytes) -> None:
        """Handle an incorrect preamble."""
        explanation = msg[1:].decode()
        if explanation != "Handshake MAC failure":
            exc = HandshakeAPIError(
                f"{self._log_name}: Handshake failure: {explanation}"
            )
        else:
            exc = InvalidEncryptionKeyAPIError(
                f"{self._log_name}: Invalid encryption key",
                self._server_name,
                self._server_mac,
            )
        self._handle_error_and_close(exc)

    def _handle_handshake(self, msg: bytes) -> None:
        if msg[0] != 0:
            self._error_on_incorrect_preamble(msg)
            return
        self._proto.read_message(msg[1:])
        self._state = NOISE_STATE_READY
        noise_protocol = self._proto.noise_protocol
        self._decrypt_cipher = DecryptCipher(noise_protocol.cipher_state_decrypt)  # pylint: disable=no-member
        self._encrypt_cipher = EncryptCipher(noise_protocol.cipher_state_encrypt)  # pylint: disable=no-member
        self.ready_future.set_result(None)

    def write_packets(
        self, packets: list[tuple[int, bytes]], debug_enabled: bool
    ) -> None:
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

    def _handle_closed(self, frame: bytes) -> None:  # pylint: disable=unused-argument
        """Handle a closed frame."""
        self._handle_error(ProtocolAPIError(f"{self._log_name}: Connection closed"))
