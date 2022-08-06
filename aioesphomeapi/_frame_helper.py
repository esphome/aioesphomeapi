import asyncio
import base64
import logging
from abc import ABC, abstractmethod
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
    @abstractmethod
    async def close(self) -> None:
        pass

    @abstractmethod
    async def write_packet(self, packet: Packet) -> None:
        pass

    @abstractmethod
    async def read_packet(self) -> Packet:
        pass


class APIPlaintextFrameHelper(APIFrameHelper):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        self._reader = reader
        self._writer = writer
        self._write_lock = asyncio.Lock()
        self._read_lock = asyncio.Lock()
        self._closed_event = asyncio.Event()

    async def close(self) -> None:
        self._closed_event.set()
        self._writer.close()

    async def write_packet(self, packet: Packet) -> None:
        data = b"\0"
        data += varuint_to_bytes(len(packet.data))
        data += varuint_to_bytes(packet.type)
        data += packet.data
        try:
            async with self._write_lock:
                _LOGGER.debug("Sending plaintext frame %s", data.hex())
                self._writer.write(data)
                await self._writer.drain()
        except (ConnectionResetError, OSError) as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def read_packet(self) -> Packet:
        async with self._read_lock:
            try:
                preamble = await self._reader.readexactly(1)
                if preamble[0] != 0x00:
                    if preamble[0] == 0x01:
                        raise RequiresEncryptionAPIError(
                            "Connection requires encryption"
                        )
                    raise ProtocolAPIError(f"Invalid preamble {preamble[0]:02x}")

                length = b""
                while not length or (length[-1] & 0x80) == 0x80:
                    length += await self._reader.readexactly(1)
                length_int = bytes_to_varuint(length)
                assert length_int is not None
                msg_type = b""
                while not msg_type or (msg_type[-1] & 0x80) == 0x80:
                    msg_type += await self._reader.readexactly(1)
                msg_type_int = bytes_to_varuint(msg_type)
                assert msg_type_int is not None

                raw_msg = b""
                if length_int != 0:
                    raw_msg = await self._reader.readexactly(length_int)
                return Packet(type=msg_type_int, data=raw_msg)
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
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        noise_psk: str,
    ):
        self._reader = reader
        self._writer = writer
        self._write_lock = asyncio.Lock()
        self._read_lock = asyncio.Lock()
        self._ready_event = asyncio.Event()
        self._closed_event = asyncio.Event()
        self._proto: Optional[NoiseConnection] = None
        self._noise_psk = noise_psk

    async def close(self) -> None:
        self._closed_event.set()
        self._writer.close()

    async def _write_frame(self, frame: bytes) -> None:
        try:
            async with self._write_lock:
                _LOGGER.debug("Sending frame %s", frame.hex())
                header = bytes(
                    [
                        0x01,
                        (len(frame) >> 8) & 0xFF,
                        len(frame) & 0xFF,
                    ]
                )
                self._writer.write(header + frame)
                await self._writer.drain()
        except OSError as err:
            raise SocketAPIError(f"Error while writing data: {err}") from err

    async def _read_frame(self) -> bytes:
        try:
            async with self._read_lock:
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
        await self._write_frame(b"")  # ClientHello
        prologue = b"NoiseAPIInit" + b"\x00\x00"

        server_hello = await self._read_frame()  # ServerHello
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
                await self._write_frame(b"\x00" + msg)
            else:
                msg = await self._read_frame()
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
        # Allow up to 60 seconds for handhsake
        try:
            async with async_timeout.timeout(60.0):
                await self._perform_handshake(expected_name)
        except asyncio.TimeoutError as err:
            raise HandshakeAPIError("Timeout during handshake") from err

    async def write_packet(self, packet: Packet) -> None:
        # Wait for handshake to complete
        await self._ready_event.wait()
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
        await self._write_frame(frame)

    async def read_packet(self) -> Packet:
        # Wait for handshake to complete
        await self._ready_event.wait()
        frame = await self._read_frame()
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
