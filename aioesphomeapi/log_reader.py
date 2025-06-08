from __future__ import annotations

# Helper script and aioesphomeapi to view logs from an esphome device
import argparse
import asyncio
import contextlib
from datetime import datetime
import logging
import sys

from .api_pb2 import SubscribeLogsResponse  # type: ignore
from .client import APIClient
from .log_parser import parse_log_message
from .log_runner import async_run


async def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser("aioesphomeapi-logs")
    parser.add_argument("--port", type=int, default=6053)
    parser.add_argument("--password", type=str)
    parser.add_argument("--noise-psk", type=str)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("address")
    args = parser.parse_args(argv[1:])

    logging.basicConfig(
        format="%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    cli = APIClient(
        args.address,
        args.port,
        args.password or "",
        noise_psk=args.noise_psk,
        keepalive=10,
    )

    def on_log(msg: SubscribeLogsResponse) -> None:
        time_ = datetime.now()
        message: bytes = msg.message
        text = message.decode("utf8", "backslashreplace")
        nanoseconds = time_.microsecond // 1000
        timestamp = (
            f"[{time_.hour:02}:{time_.minute:02}:{time_.second:02}.{nanoseconds:03}]"
        )

        # Parse and print the log message
        for line in parse_log_message(text, timestamp):
            print(line)

    stop = await async_run(cli, on_log)
    try:
        await asyncio.Event().wait()
    finally:
        await stop()


def cli_entry_point() -> None:
    """Run the CLI."""
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main(sys.argv))


if __name__ == "__main__":
    cli_entry_point()
    sys.exit(0)
