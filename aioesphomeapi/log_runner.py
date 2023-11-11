from __future__ import annotations

import logging
from typing import Any, Callable, Coroutine

import zeroconf

from .api_pb2 import SubscribeLogsResponse  # type: ignore
from .client import APIClient
from .core import APIConnectionError
from .model import LogLevel
from .reconnect_logic import ReconnectLogic

_LOGGER = logging.getLogger(__name__)


async def async_run_logs(
    cli: APIClient,
    on_log: Callable[[SubscribeLogsResponse], None],
    log_level: LogLevel = LogLevel.LOG_LEVEL_VERY_VERBOSE,
    zeroconf_instance: zeroconf.Zeroconf | None = None,
    dump_config: bool = True,
) -> Callable[[], Coroutine[Any, Any, None]]:
    """Run logs until canceled.

    Returns a coroutine that can be awaited to stop the logs.
    """

    dumped_config = not dump_config

    async def on_connect() -> None:
        """Handle a connection."""
        nonlocal dumped_config
        try:
            await cli.subscribe_logs(
                on_log,
                log_level=log_level,
                dump_config=not dumped_config,
            )
            dumped_config = True
        except APIConnectionError:
            await cli.disconnect()

    async def on_disconnect(  # pylint: disable=unused-argument
        expected_disconnect: bool,
    ) -> None:
        _LOGGER.warning("Disconnected from API")

    passed_in_zeroconf = zeroconf_instance is not None
    zc = zeroconf_instance or zeroconf.Zeroconf()
    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=zc,
    )
    await logic.start()

    async def _stop() -> None:
        if not passed_in_zeroconf:
            zc.close()
        await logic.stop()
        await cli.disconnect()

    return _stop
