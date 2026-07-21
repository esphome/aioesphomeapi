# ruff: noqa: T201
import asyncio

from aioesphomeapi.client import APIClient
from aioesphomeapi.model import LogLevel


async def main() -> None:
    """Connect to an ESPHome device and get details."""
    # Establish connection
    api = APIClient(
        "28:CD:C1:06:BD:12",
        port=0x80,
        transport="ble",
        ble_address_type="public",
        password="",
        noise_psk="iOZqtvw31Yy6sasRl5h2DElG2VDlqW2WjJEKObVN8bg=",
    )
    api.set_debug(True)
    await api.connect(login=True)
    print(api.api_version)

    # Show device details
    device_info = await api.device_info()
    print(device_info)
    api.subscribe_logs(
        log_level=LogLevel.LOG_LEVEL_INFO,
        dump_config=True,
        on_log=lambda m: print(m.message.decode("utf-8")),
    )
    api.subscribe_states(print)
    # List all entities of the device
    entities = await api.list_entities_services()
    print(entities)
    while True:
        api.switch_command(key=3910721477, device_id=0, state=True)
        api.switch_command(key=3910721477, device_id=0, state=True)
        await asyncio.sleep(0.2)
        api.switch_command(key=3910721477, device_id=0, state=False)
        await asyncio.sleep(0.3)


asyncio.run(main())
