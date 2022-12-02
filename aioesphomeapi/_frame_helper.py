import asyncio
import base64
import logging
from abc import ABC, abstractmethod, abstractproperty
from dataclasses import dataclass
from typing import Optional

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


@dataclass
class Packet:
    type: int
    data: bytes


class APIFrameHelper(ABC):
    """Helper class to handle the API frame protocol."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Initialize the API frame helper."""
        self._reader = reader
        self._writer = writer
        self.read_lock = asyncio.Lock()
        self._closed_event = asyncio.Event()

    @abstractproperty  # pylint: disable=deprecated-decorator
    def ready(self) -> bool:
        """Return if the connection is ready."""

    @abstractmethod
    async def close(self) -> None:
        """Close the connection."""

    @abstractmethod
    def write_packet(self, packet: Packet) -> None:
        """Write a packet to the socket."""

    @abstractmethod
    async def read_packet_with_lock(self) -> Packet:
        """Read a packet from the socket, the caller is responsible for having the lock."""

    @abstractmethod
    async def wait_for_ready(self) -> None:
        """Wait for the connection to be ready."""


class APIPlaintextFrameHelper(APIFrameHelper):
    """Frame helper for plaintext API connections."""

    async def close(self) -> None:
        """Close the connection."""
        self._closed_event.set()
        self._writer.close()

    @property
    def ready(self) -> bool:
        """Return if the connection is ready."""
        # Plaintext is always ready
        return True

    def write_packet(self, packet: Packet) -> None:
        """Write a packet to the socket, the caller should not have the lock.

        The entire packet must be written in a single call to write
        to avoid locking.
        """
        data = (
            b"\0"
            + varuint_to_bytes(len(packet.data))
            + varuint_to_bytes(packet.type)
            + packet.data
        )
        _LOGGER.debug("Sending plaintext frame %s", data.hex())

        try:
            self._writer.write(data)
        except (ConnectionResetError, OSError) as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def wait_for_ready(self) -> None:
        """Wait for the connection to be ready."""
        # No handshake for plaintext

    async def read_packet_with_lock(self) -> Packet:
        """Read a packet from the socket, the caller is responsible for having the lock."""
        assert self.read_lock.locked(), "read_packet_with_lock called without lock"
        try:
            # Read preamble, which should always 0x00
            # Also try to get the length and msg type
            # to avoid multiple calls to readexactly
            init_bytes = await self._reader.readexactly(3)
            if init_bytes[0] != 0x00:
                if init_bytes[0] == 0x01:
                    raise RequiresEncryptionAPIError("Connection requires encryption")
                raise ProtocolAPIError(f"Invalid preamble {init_bytes[0]:02x}")

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
                length += await self._reader.readexactly(1)

            # If the message length was longer than 1 byte, we need to read the
            # message type
            while not msg_type or (msg_type[-1] & 0x80) == 0x80:
                msg_type += await self._reader.readexactly(1)

            length_int = bytes_to_varuint(length)
            assert length_int is not None
            msg_type_int = bytes_to_varuint(msg_type)
            assert msg_type_int is not None

            if length_int == 0:
                return Packet(type=msg_type_int, data=b"")

            data = await self._reader.readexactly(length_int)
            return Packet(type=msg_type_int, data=data)
        except (asyncio.IncompleteReadError, OSError, TimeoutError) as err:
            if (
                isinstance(err, asyncio.IncompleteReadError)
                and self._closed_event.is_set()
            ):
                raise SocketClosedAPIError(
                    f"Socket closed while reading data: {err}"
                ) from err
            raise SocketAPIError(f"Error while reading data: {err}") from err


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


class APINoiseFrameHelper(APIFrameHelper):
    """Frame helper for noise encrypted connections."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        noise_psk: str,
    ) -> None:
        """Initialize the API frame helper."""
        super().__init__(reader, writer)
        self._ready_event = asyncio.Event()
        self._proto: Optional[NoiseConnection] = None
        self._noise_psk = noise_psk

    @property
    def ready(self) -> bool:
        """Return if the connection is ready."""
        return self._ready_event.is_set()

    async def close(self) -> None:
        """Close the connection."""
        # Make sure we set the ready event if its not already set
        # so that we don't block forever on the ready event if we
        # are waiting for the handshake to complete.
        self._ready_event.set()
        self._closed_event.set()
        self._writer.close()

    def _write_frame(self, frame: bytes) -> None:
        """Write a packet to the socket, the caller should not have the lock.

        The entire packet must be written in a single call to write
        to avoid locking.
        """
        _LOGGER.debug("Sending frame %s", frame.hex())

        try:
            header = bytes(
                [
                    0x01,
                    (len(frame) >> 8) & 0xFF,
                    len(frame) & 0xFF,
                ]
            )
            self._writer.write(header + frame)
        except OSError as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def _read_frame_with_lock(self) -> bytes:
        """Read a frame from the socket, the caller is responsible for having the lock."""
        assert self.read_lock.locked(), "_read_frame_with_lock called without lock"
        try:
            header = await self._reader.readexactly(3)
            if header[0] != 0x01:
                raise ProtocolAPIError(f"Marker byte invalid: {header[0]}")
            msg_size = (header[1] << 8) | header[2]
            frame = await self._reader.readexactly(msg_size)
        except (asyncio.IncompleteReadError, OSError, TimeoutError) as err:
            if (
                isinstance(err, asyncio.IncompleteReadError)
                and self._closed_event.is_set()
            ):
                raise SocketClosedAPIError(
                    f"Socket closed while reading data: {err}"
                ) from err
            raise SocketAPIError(f"Error while reading data: {err}") from err

        _LOGGER.debug("Received frame %s", frame.hex())
        return frame

    async def _perform_handshake(self, expected_name: Optional[str]) -> None:
        """Perform the handshake with the server, the caller is responsible for having the lock."""
        assert self.read_lock.locked(), "_perform_handshake called without lock"
        self._write_frame(b"")  # ClientHello
        prologue = b"NoiseAPIInit" + b"\x00\x00"

        server_hello = await self._read_frame_with_lock()  # ServerHello
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
            if expected_name is not None and expected_name != server_name:
                raise BadNameAPIError(
                    f"Server sent a different name '{server_name}'", server_name
                )

        self._proto = NoiseConnection.from_name(b"Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        self._proto.set_as_initiator()
        self._proto.set_psks(_decode_noise_psk(self._noise_psk))
        self._proto.set_prologue(prologue)
        self._proto.start_handshake()

        _LOGGER.debug("Starting handshake...")
        do_write = True
        while not self._proto.handshake_finished:
            if do_write:
                msg = self._proto.write_message()
                self._write_frame(b"\x00" + msg)
            else:
                msg = await self._read_frame_with_lock()
                if not msg:
                    raise HandshakeAPIError("Handshake message too short")
                if msg[0] != 0:
                    explanation = msg[1:].decode()
                    if explanation == "Handshake MAC failure":
                        raise InvalidEncryptionKeyAPIError("Invalid encryption key")
                    raise HandshakeAPIError(f"Handshake failure: {explanation}")
                self._proto.read_message(msg[1:])

            do_write = not do_write

        _LOGGER.debug("Handshake complete!")
        self._ready_event.set()

    async def perform_handshake(self, expected_name: Optional[str]) -> None:
        """Perform the handshake with the server."""
        # Allow up to 60 seconds for handhsake
        try:
            async with self.read_lock, async_timeout.timeout(60.0):
                await self._perform_handshake(expected_name)
        except asyncio.TimeoutError as err:
            raise HandshakeAPIError("Timeout during handshake") from err

    def write_packet(self, packet: Packet) -> None:
        """Write a packet to the socket."""
        padding = 0
        data = (
            bytes(
                [
                    (packet.type >> 8) & 0xFF,
                    (packet.type >> 0) & 0xFF,
                    (len(packet.data) >> 8) & 0xFF,
                    (len(packet.data) >> 0) & 0xFF,
                ]
            )
            + packet.data
            + b"\x00" * padding
        )
        assert self._proto is not None
        frame = self._proto.encrypt(data)
        self._write_frame(frame)

    async def wait_for_ready(self) -> None:
        """Wait for the connection to be ready."""
        await self._ready_event.wait()

    async def read_packet_with_lock(self) -> Packet:
        """Read a packet from the socket, the caller is responsible for having the lock."""
        frame = await self._read_frame_with_lock()
        assert self._proto is not None
        msg = self._proto.decrypt(frame)
        if len(msg) < 4:
            raise ProtocolAPIError(f"Bad packet frame: {msg}")
        pkt_type = (msg[0] << 8) | msg[1]
        data_len = (msg[2] << 8) | msg[3]
        if data_len + 4 > len(msg):
            raise ProtocolAPIError(f"Bad data len: {data_len} vs {len(msg)}")
        data = msg[4 : 4 + data_len]
        return Packet(type=pkt_type, data=data)
