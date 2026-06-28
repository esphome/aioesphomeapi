import os
import aioesphomeapi
import asyncio

from aioesphomeapi.model import LogLevel


async def main():
    """Connect to an ESPHome device and get details."""

    # Establish connection
    api = aioesphomeapi.APIClient(
        "CA:28:BA:F0:A4:D6",
        port=0x44,
        connection_type="ble",
        password="",
    )
    api.set_debug(True)
    await api.connect(login=True)
    api.send_home_assistant_state(
        "test",
        "test",
        "testaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    # Get API version of the device's firmware
    print(api.api_version)

    # Show device details
    device_info = await api.device_info()
    print(device_info)
    #api.subscribe_logs(
    #    log_level=LogLevel.LOG_LEVEL_INFO,
    #    dump_config=True,
    #    on_log=lambda m: print(m.message.decode("utf-8")),
    #)
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
