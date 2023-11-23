import timeit
from functools import partial

from aioesphomeapi import APIConnection
from aioesphomeapi._frame_helper import APIPlaintextFrameHelper
from aioesphomeapi._frame_helper.plain_text import _cached_varuint_to_bytes
from aioesphomeapi.api_pb2 import (
    BluetoothLERawAdvertisement,
    BluetoothLERawAdvertisementsResponse,
)
from aioesphomeapi.client import APIClient

# cythonize -X language_level=3 -a -i aioesphomeapi/_frame_helper/plain_text.py
# cythonize -X language_level=3 -a -i aioesphomeapi/_frame_helper/base.py
# cythonize -X language_level=3 -a -i aioesphomeapi/connection.py


class MockConnection(APIConnection):
    pass


client = APIClient("fake.address", 6052, None)
connection = MockConnection(client._params, lambda expected_disconnect: None, None)


def process_incoming_msg():
    connection.process_packet(
        93,
        b'\n\xb2\x01\x08\x01\x10\xab\x01\x18\x02"\xa8\x016c04010134000000'
        b"e25389019500000001016f00250000002f6f72672f626c75657a2f686369302"
        b"f64656c04010134000000e25389019500000001016f00250000002f6f72672f"
        b"626c75657a2f686369302f6465\n\xb2\x01\x08\x01\x10\xab\x01\x18\x02"
        b'"\xa8\x016c04010134000000e25389019500000001016f00250000002f6f726'
        b"72f626c75657a2f686369302f64656c04010134000000e253890195000000010"
        b"16f00250000002f6f72672f626c75657a2f686369302f6465\n\xb2\x01\x08"
        b'\x01\x10\xab\x01\x18\x02"\xa8\x016c04010134000000e25389019500000'
        b"001016f00250000002f6f72672f626c75657a2f686369302f64656c040101340"
        b"00000e25389019500000001016f00250000002f6f72672f626c75657a2f68636"
        b'9302f6465\n\xb2\x01\x08\x01\x10\xab\x01\x18\x02"\xa8\x016c040101'
        b"34000000e25389019500000001016f00250000002f6f72672f626c75657a2f68"
        b"6369302f64656c04010134000000e25389019500000001016f00250000002f6f"
        b"72672f626c75657a2f686369302f6465\n\xb2\x01\x08\x01\x10\xab\x01"
        b'\x18\x02"\xa8\x016c04010134000000e25389019500000001016f002500000'
        b"02f6f72672f626c75657a2f686369302f64656c04010134000000e2538901950"
        b"0000001016f00250000002f6f72672f626c75657a2f686369302f6465",
    )


def on_advertisements(msgs: list[BluetoothLERawAdvertisement]):
    pass


connection.add_message_callback(
    partial(client._on_ble_raw_advertisement_response, on_advertisements),
    (BluetoothLERawAdvertisementsResponse,),
)

count = 3000000
time = timeit.Timer(process_incoming_msg).timeit(count)
print(f"Processed {count} bluetooth messages took {time} seconds")
