import timeit

from aioesphomeapi import APIConnection
from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.plain_text import _cached_varuint_to_bytes
from aioesphomeapi.api_pb2 import (
    BluetoothLERawAdvertisement,
    BluetoothLERawAdvertisementsResponse,
)

# cythonize -X language_level=3 -a -i aioesphomeapi/_frame_helper/plain_text.py
# cythonize -X language_level=3 -a -i aioesphomeapi/_frame_helper/base.py
# cythonize -X language_level=3 -a -i aioesphomeapi/connection.py

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
    b"\0" + _cached_varuint_to_bytes(len(data)) + _cached_varuint_to_bytes(type_) + data
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


def process_incoming_msg():
    helper.data_received(data)


count = 3000000
time = timeit.Timer(process_incoming_msg).timeit(count)
print(f"Processed {count} bluetooth messages took {time} seconds")
