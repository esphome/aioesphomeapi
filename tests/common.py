from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from functools import partial
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from google.protobuf import message
from noise.connection import NoiseConnection  # type: ignore[import-untyped]
from zeroconf import Zeroconf
from zeroconf.asyncio import AsyncZeroconf

from aioesphomeapi import APIClient, APIConnection
from aioesphomeapi._frame_helper.noise import APINoiseFrameHelper
from aioesphomeapi._frame_helper.noise_encryption import (
    ESPHOME_NOISE_BACKEND,
    EncryptCipher,
)
from aioesphomeapi._frame_helper.packets import _cached_varuint_to_bytes
from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.api_pb2 import (
    AuthenticationResponse,
    HelloResponse,
    PingRequest,
    PingResponse,
)
from aioesphomeapi.client import ConnectionParams
from aioesphomeapi.core import MESSAGE_TYPE_TO_PROTO, SocketClosedAPIError
from aioesphomeapi.zeroconf import ZeroconfManager

UTC = timezone.utc
_MONOTONIC_RESOLUTION = time.get_clock_info("monotonic").resolution
# We use a partial here since it is implemented in native code
# and avoids the global lookup of UTC
utcnow: partial[datetime] = partial(datetime.now, UTC)
utcnow.__doc__ = "Get now in UTC time."

PROTO_TO_MESSAGE_TYPE = {v: k for k, v in MESSAGE_TYPE_TO_PROTO.items()}


PREAMBLE = b"\x00"

NOISE_HELLO = b"\x01\x00\x00"
KEEP_ALIVE_INTERVAL = 15.0


def get_mock_connection_params() -> ConnectionParams:
    return ConnectionParams(
        addresses=["fake.address"],
        port=6052,
        password=None,
        client_info="Tests client",
        keepalive=KEEP_ALIVE_INTERVAL,
        zeroconf_manager=ZeroconfManager(),
        noise_psk=None,
        expected_name=None,
        expected_mac=None,
    )


def mock_data_received(
    protocol: APINoiseFrameHelper | APIPlaintextFrameHelper, data: bytes
) -> None:
    """Mock data received on the protocol."""
    try:
        protocol.data_received(data)
    except Exception as err:  # pylint: disable=broad-except
        loop = asyncio.get_running_loop()
        loop.call_soon(
            protocol.connection_lost,
            err,
        )


def get_mock_zeroconf() -> MagicMock:
    with patch("zeroconf.Zeroconf.start"):
        zc = Zeroconf()
        zc.close = MagicMock()
    return zc


def get_mock_async_zeroconf() -> AsyncZeroconf:
    aiozc = AsyncZeroconf(zc=get_mock_zeroconf())
    aiozc.async_close = AsyncMock()
    return aiozc


class Estr(str):
    """A subclassed string."""

    __slots__ = ()


def generate_split_plaintext_packet(msg: message.Message) -> list[bytes]:
    type_ = PROTO_TO_MESSAGE_TYPE[msg.__class__]
    bytes_ = msg.SerializeToString()
    return [
        b"\0",
        _cached_varuint_to_bytes(len(bytes_)),
        _cached_varuint_to_bytes(type_),
        bytes_,
    ]


def generate_plaintext_packet(msg: message.Message) -> bytes:
    return b"".join(generate_split_plaintext_packet(msg))


def as_utc(dattim: datetime) -> datetime:
    """Return a datetime as UTC time."""
    if dattim.tzinfo == UTC:
        return dattim
    return dattim.astimezone(UTC)


def async_fire_time_changed(
    datetime_: datetime | None = None, fire_all: bool = False
) -> None:
    """Fire a time changed event at an exact microsecond.

    Consider that it is not possible to actually achieve an exact
    microsecond in production as the event loop is not precise enough.
    If your code relies on this level of precision, consider a different
    approach, as this is only for testing.
    """
    loop = asyncio.get_running_loop()
    utc_datetime = datetime.now(UTC) if datetime_ is None else as_utc(datetime_)

    timestamp = utc_datetime.timestamp()
    for task in list(loop._scheduled):
        if not isinstance(task, asyncio.TimerHandle):
            continue
        if task.cancelled():
            continue

        mock_seconds_into_future = timestamp - time.time()
        future_seconds = task.when() - (loop.time() + _MONOTONIC_RESOLUTION)

        if fire_all or mock_seconds_into_future >= future_seconds:
            task._run()
            task.cancel()


async def connect(conn: APIConnection, login: bool = True):
    """Wrapper for connection logic to do both parts."""
    await conn.start_resolve_host()
    await conn.start_connection()
    await conn.finish_connection(login=login)


async def connect_client(
    client: APIClient,
    login: bool = True,
    on_stop: Callable[[bool], Awaitable[None]] | None = None,
) -> None:
    """Wrapper for connection logic to do both parts."""
    await client.start_resolve_host(on_stop=on_stop)
    await client.start_connection()
    await client.finish_connection(login=login)


def send_plaintext_hello(
    protocol: APIPlaintextFrameHelper,
    major: int | None = None,
    minor: int | None = None,
) -> None:
    hello_response: message.Message = HelloResponse()
    hello_response.api_version_major = 1 if major is None else major
    hello_response.api_version_minor = 9 if minor is None else minor
    hello_response.name = "fake"
    protocol.data_received(generate_plaintext_packet(hello_response))


def send_plaintext_auth_response(
    protocol: APIPlaintextFrameHelper, invalid_password: bool
) -> None:
    auth_response: message.Message = AuthenticationResponse()
    auth_response.invalid_password = invalid_password
    protocol.data_received(generate_plaintext_packet(auth_response))


def send_ping_response(protocol: APIPlaintextFrameHelper) -> None:
    ping_response: message.Message = PingResponse()
    protocol.data_received(generate_plaintext_packet(ping_response))


def send_ping_request(protocol: APIPlaintextFrameHelper) -> None:
    ping_request: message.Message = PingRequest()
    protocol.data_received(generate_plaintext_packet(ping_request))


def get_mock_protocol(conn: APIConnection):
    protocol = APIPlaintextFrameHelper(
        connection=conn,
        client_info="mock",
        log_name="mock_device",
    )
    transport = MagicMock()
    protocol.connection_made(transport)
    return protocol


def _create_mock_transport_protocol(
    transport: asyncio.Transport,
    connected: asyncio.Event,
    create_func: Callable[[], APIPlaintextFrameHelper],
    **kwargs,
) -> tuple[asyncio.Transport, APIPlaintextFrameHelper]:
    protocol: APIPlaintextFrameHelper = create_func()
    protocol.connection_made(transport)
    connected.set()
    return transport, protocol


def _extract_encrypted_payload_from_handshake(handshake_pkt: bytes) -> bytes:
    noise_hello = handshake_pkt[0:3]
    pkt_header = handshake_pkt[3:6]
    assert noise_hello == NOISE_HELLO
    assert pkt_header[0] == 1  # type
    pkg_length_high = pkt_header[1]
    pkg_length_low = pkt_header[2]
    pkg_length = (pkg_length_high << 8) + pkg_length_low
    assert pkg_length == 49
    noise_prefix = handshake_pkt[6:7]
    assert noise_prefix == b"\x00"
    return handshake_pkt[7:]


def _make_noise_hello_pkt(hello_pkt: bytes) -> bytes:
    """Make a noise hello packet."""
    preamble = 1
    hello_pkg_length = len(hello_pkt)
    hello_pkg_length_high = (hello_pkg_length >> 8) & 0xFF
    hello_pkg_length_low = hello_pkg_length & 0xFF
    hello_header = bytes((preamble, hello_pkg_length_high, hello_pkg_length_low))
    return hello_header + hello_pkt


def _make_noise_handshake_pkt(proto: NoiseConnection) -> bytes:
    handshake = proto.write_message(b"")
    handshake_pkt = b"\x00" + handshake
    preamble = 1
    handshake_pkg_length = len(handshake_pkt)
    handshake_pkg_length_high = (handshake_pkg_length >> 8) & 0xFF
    handshake_pkg_length_low = handshake_pkg_length & 0xFF
    handshake_header = bytes(
        (preamble, handshake_pkg_length_high, handshake_pkg_length_low)
    )

    return handshake_header + handshake_pkt


def _make_encrypted_packet(
    cipher: EncryptCipher, msg_type: int, payload: bytes
) -> bytes:
    msg_type = 42
    msg_type_high = (msg_type >> 8) & 0xFF
    msg_type_low = msg_type & 0xFF
    msg_length = len(payload)
    msg_length_high = (msg_length >> 8) & 0xFF
    msg_length_low = msg_length & 0xFF
    msg_header = bytes((msg_type_high, msg_type_low, msg_length_high, msg_length_low))
    encrypted_payload = cipher.encrypt(msg_header + payload)
    return _make_encrypted_packet_from_encrypted_payload(encrypted_payload)


def _make_encrypted_packet_from_encrypted_payload(encrypted_payload: bytes) -> bytes:
    preamble = 1
    encrypted_pkg_length = len(encrypted_payload)
    encrypted_pkg_length_high = (encrypted_pkg_length >> 8) & 0xFF
    encrypted_pkg_length_low = encrypted_pkg_length & 0xFF
    encrypted_header = bytes(
        (preamble, encrypted_pkg_length_high, encrypted_pkg_length_low)
    )
    return encrypted_header + encrypted_payload


def _mock_responder_proto(psk_bytes: bytes) -> NoiseConnection:
    proto = NoiseConnection.from_name(
        b"Noise_NNpsk0_25519_ChaChaPoly_SHA256", backend=ESPHOME_NOISE_BACKEND
    )
    proto.set_as_responder()
    proto.set_psks(psk_bytes)
    proto.set_prologue(b"NoiseAPIInit\x00\x00")
    proto.start_handshake()
    return proto


def _make_mock_connection() -> tuple[APIConnection, list[tuple[int, bytes]]]:
    """Make a mock connection."""
    packets: list[tuple[int, bytes]] = []

    class MockConnection(APIConnection):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            """Swallow args."""
            super().__init__(
                get_mock_connection_params(), AsyncMock(), True, None, *args, **kwargs
            )

        def process_packet(self, type_: int, data: bytes):
            packets.append((type_, data))

    connection = MockConnection()
    return connection, packets


class MockAPINoiseFrameHelper(APINoiseFrameHelper):
    def __init__(self, *args: Any, writer: Any | None = None, **kwargs: Any) -> None:
        """Swallow args."""
        super().__init__(*args, **kwargs)
        transport = MagicMock()
        transport.writelines = writer or MagicMock()
        self.__transport = transport
        self.connection_made(transport)

    def connection_made(self, transport: Any) -> None:
        return super().connection_made(self.__transport)

    def mock_write_frame(self, frame: bytes) -> None:
        """Write a packet to the socket.

        The entire packet must be written in a single call to write.
        """
        frame_len = len(frame)
        header = bytes((0x01, (frame_len >> 8) & 0xFF, frame_len & 0xFF))
        try:
            self._writelines([header, frame])
        except (RuntimeError, ConnectionResetError, OSError) as err:
            raise SocketClosedAPIError(
                f"{self._log_name}: Error while writing data: {err}"
            ) from err
