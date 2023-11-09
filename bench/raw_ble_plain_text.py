import io
import timeit

from aioesphomeapi.api_pb2 import (
    BluetoothLERawAdvertisementsResponse,
    BluetoothLERawAdvertisement,
)
from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.plain_text import _cached_varuint_to_bytes

# cythonize -X language_level=3 -a -i aioesphomeapi/_frame_helper/plain_text.py
# cythonize -X language_level=3 -a -i aioesphomeapi/_frame_helper/base.py

adv = BluetoothLERawAdvertisementsResponse()
fake_adv = BluetoothLERawAdvertisement(
    address=1,
    rssi=-86,
    address_type=2,
    data=b"6c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f64656c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f6465",
)
for i in range(5):
    adv.advertisements.append(fake_adv)

type_ = 93
data = adv.SerializeToString()
data = (
    b"\0" + _cached_varuint_to_bytes(len(data)) + _cached_varuint_to_bytes(type_) + data
)


def _packet(type_: int, data: bytes):
    pass


def _on_error(exc: Exception):
    raise exc


helper = APIPlaintextFrameHelper(
    on_pkt=_packet, on_error=_on_error, client_info="my client", log_name="test"
)


def process_incoming_msg():
    helper.data_received(data)


count = 3000000
time = timeit.Timer(process_incoming_msg).timeit(count)
print(f"Processed {count} bluetooth messages took {time} seconds")
