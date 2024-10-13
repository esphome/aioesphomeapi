"""Benchmarks."""

from functools import partial

from pytest_codspeed import BenchmarkFixture  # type: ignore[import-untyped]

from aioesphomeapi import APIConnection
from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.plain_text import _cached_varuint_to_bytes
from aioesphomeapi.api_pb2 import (
    BluetoothLERawAdvertisement,
    BluetoothLERawAdvertisementsResponse,
)
from aioesphomeapi.client import APIClient


def test_raw_ble_plain_text_with_callback(benchmark: BenchmarkFixture) -> None:
    """Benchmark raw BLE plaintext with callback."""

    class MockConnection(APIConnection):
        pass

    client = APIClient("fake.address", 6052, None)
    connection = MockConnection(
        client._params, lambda expected_disconnect: None, False, None
    )

    process_incoming_msg = partial(
        connection.process_packet,
        93,
        b'\n$\x08\xe3\x8a\x83\xad\x9c\xa3\x1d\x10\xbd\x01\x18\x01"\x15\x02\x01\x1a'
        b"\x02\n\x06\x0e\xffL\x00\x0f\x05\x90\x00\xb5B\x9c\x10\x02)\x04\n!"
        b'\x08\x9e\x9a\xb1\xfc\x9e\x890\x10\xbf\x01"\x14\x02\x01\x06\x10\xff\xa9\x0b'
        b"\x01\x05\x00\x0b\x04\x18\n\x1cM\x8c\xefI\xc0\n.\x08\x9f\x89\x85\xe6"
        b'\xf3\xe8\x17\x10\x8d\x01\x18\x01"\x1f\x02\x01\x02\x14\xff\xa7'
        b"\x05\x06\x00\x12 %\x00\xca\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x02\n"
        b'\x0f\x03\x03\x07\xfe\n\x1f\x08\x9e\xbf\xb5\x87\x98\xce7\x10_\x18\x01"'
        b"\x11\x02\x01\x06\r\xffi\t\xdeq\x80\xed_\x9e\x0bC\x08 \n \x08\xc6\x8a\xa9"
        b'\xed\xb9\xc4>\x10\xab\x01\x18\x01"\x11\x02\x01\x06\x07\xff\t\x04\x8c\x01'
        b'a\x01\x05\tRZSS\n \x08\xd7\xc6\xe8\xe8\x91\xb85\x10\xa5\x01\x18\x01"'
        b"\x11\x02\x01\x06\x07\xff\t\x04\x8c\x01`\x01\x05\tRZSS\n-\x08\xca\xb0\x91"
        b'\xf4\xbc\xe6<\x10}\x18\x01"\x1f\x02\x01\x04\x03\x03\x07\xfe\x14\xff\xa7'
        b"\x05\x06\x00\x12 %\x00\xca\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x02\n"
        b'\x00\n)\x08\xf9\xdd\x95\xac\xb9\x95\r\x10\x87\x01"\x1c\x02\x01\x06\x03'
        b"\x03\x12\x18\x10\tLOOKin_98F330B4\x03\x19\xc1\x03",
    )

    def on_advertisements(msgs: list[BluetoothLERawAdvertisement]):
        """Callback for advertisements."""

    connection.add_message_callback(
        on_advertisements,
        (BluetoothLERawAdvertisementsResponse,),
    )

    benchmark(process_incoming_msg)


def test_raw_ble_plain_text(benchmark: BenchmarkFixture) -> None:
    """Benchmark raw BLE plaintext."""
    adv = BluetoothLERawAdvertisementsResponse()
    fake_adv = BluetoothLERawAdvertisement(
        address=1,
        rssi=-86,
        address_type=2,
        data=(
            b"6c04010134000000e25389019500000001016f00250000002f6f72672f626c75"
            b"657a2f686369302f64656c04010134000000e25389019500000001016f002500"
            b"00002f6f72672f626c75657a2f686369302f6465"
        ),
    )
    for i in range(5):
        adv.advertisements.append(fake_adv)

    type_ = 93
    data = adv.SerializeToString()
    data = (
        b"\0"
        + _cached_varuint_to_bytes(len(data))
        + _cached_varuint_to_bytes(type_)
        + data
    )

    class MockConnection(APIConnection):
        def __init__(self, *args, **kwargs):
            pass

        def process_packet(self, type_: int, data: bytes):
            pass

        def report_fatal_error(self, exc: Exception):
            raise exc

    connection = MockConnection()

    helper = APIPlaintextFrameHelper(
        connection=connection, client_info="my client", log_name="test"
    )

    process_incoming_msg = partial(helper.data_received, data)

    benchmark(process_incoming_msg)
