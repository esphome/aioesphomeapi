from __future__ import annotations

import logging
from typing import Any, Callable, Coroutine

import zeroconf
from core import APIConnectionError

from .api_pb2 import SubscribeLogsResponse  # type: ignore
from .client import APIClient
from .model import LogLevel
from .reconnect_logic import ReconnectLogic

_LOGGER = logging.getLogger(__name__)


async def async_run_logs(
    cli: APIClient,
    on_log: Callable[[SubscribeLogsResponse], None],
    log_level: LogLevel = LogLevel.LOG_LEVEL_VERY_VERBOSE,
    zeroconf_instance: zeroconf.Zeroconf | None = None,
    dump_config: bool = True,
) -> Coroutine[Any, Any, None]:
    """Run logs until canceled.

    Returns a coroutine that can be awaited to stop the logs.
    """

    has_connects = dump_config

    async def on_connect() -> None:
        nonlocal has_connects
        try:
            await cli.subscribe_logs(
                on_log,
                log_level=log_level,
                dump_config=not has_connects,
            )
            has_connects = True
        except APIConnectionError:
            await cli.disconnect()

    async def on_disconnect(  # pylint: disable=unused-argument
        expected_disconnect: bool,
    ) -> None:
        _LOGGER.warning("Disconnected from API")

    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=zeroconf_instance or zeroconf.Zeroconf(),
    )
    await logic.start()
    return logic.stop
