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
        b'\n\xb2\x01\x08\x01\x10\xab\x01\x18\x02"\xa8\x016c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f64656c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f6465\n\xb2\x01\x08\x01\x10\xab\x01\x18\x02"\xa8\x016c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f64656c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f6465\n\xb2\x01\x08\x01\x10\xab\x01\x18\x02"\xa8\x016c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f64656c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f6465\n\xb2\x01\x08\x01\x10\xab\x01\x18\x02"\xa8\x016c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f64656c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f6465\n\xb2\x01\x08\x01\x10\xab\x01\x18\x02"\xa8\x016c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f64656c04010134000000e25389019500000001016f00250000002f6f72672f626c75657a2f686369302f6465',
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
