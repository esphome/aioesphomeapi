# Helper script and aioesphomeapi to view logs from an esphome device
import argparse
import asyncio
import logging
import sys
from datetime import datetime
from typing import List

import zeroconf

from aioesphomeapi.api_pb2 import SubscribeLogsResponse  # type: ignore
from aioesphomeapi.client import APIClient
from aioesphomeapi.core import APIConnectionError
from aioesphomeapi.model import LogLevel
from aioesphomeapi.reconnect_logic import ReconnectLogic

_LOGGER = logging.getLogger(__name__)


async def main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser("aioesphomeapi-logs")
    parser.add_argument("--port", type=int, default=6053)
    parser.add_argument("--password", type=str)
    parser.add_argument("--noise-psk", type=str)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("address")
    args = parser.parse_args(argv[1:])

    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    cli = APIClient(
        asyncio.get_event_loop(),
        args.address,
        args.port,
        args.password or "",
        noise_psk=args.noise_psk,
        keepalive=10,
    )

    def on_log(msg: SubscribeLogsResponse) -> None:
        time_ = datetime.now().time().strftime("[%H:%M:%S]")
        text = msg.message
        print(time_ + text.decode("utf8", "backslashreplace"))

    has_connects = False

    async def on_connect() -> None:
        nonlocal has_connects
        try:
            await cli.subscribe_logs(
                on_log,
                log_level=LogLevel.LOG_LEVEL_VERY_VERBOSE,
                dump_config=not has_connects,
            )
            has_connects = True
        except APIConnectionError:
            cli.disconnect()

    async def on_disconnect() -> None:
        _LOGGER.warning("Disconnected from API")

    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=zeroconf.Zeroconf(),
    )
    await logic.start()
    try:
        while True:
            await asyncio.sleep(60)
    except KeyboardInterrupt:
        await logic.stop()


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv)) or 0)
