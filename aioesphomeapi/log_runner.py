from __future__ import annotations

from collections.abc import Callable, Coroutine
import logging
from typing import Any

from zeroconf.asyncio import AsyncZeroconf

from .api_pb2 import SubscribeLogsResponse  # type: ignore
from .client import APIClient
from .core import APIConnectionError
from .model import EntityInfo, EntityState, LogLevel
from .reconnect_logic import ReconnectLogic
from .state_log_formatter import format_state_log

_LOGGER = logging.getLogger(__name__)


async def async_run(
    cli: APIClient,
    on_log: Callable[[SubscribeLogsResponse], None],
    log_level: LogLevel = LogLevel.LOG_LEVEL_VERY_VERBOSE,
    aio_zeroconf_instance: AsyncZeroconf | None = None,
    dump_config: bool = True,
    name: str | None = None,
    subscribe_states: bool = True,
) -> Callable[[], Coroutine[Any, Any, None]]:
    """Run logs until canceled.

    Returns a coroutine that can be awaited to stop the logs.
    """
    dumped_config = not dump_config

    async def on_connect() -> None:
        """Handle a connection."""
        nonlocal dumped_config
        try:
            cli.subscribe_logs(
                on_log,
                log_level=log_level,
                dump_config=not dumped_config,
            )
            dumped_config = True

            if subscribe_states:
                await _subscribe_entity_states(cli, on_log)
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
        zeroconf_instance=aio_zeroconf_instance,
        name=name,
    )
    await logic.start()

    async def _stop() -> None:
        await logic.stop()
        await cli.disconnect()

    return _stop


async def _subscribe_entity_states(
    cli: APIClient,
    on_log: Callable[[SubscribeLogsResponse], None],
) -> None:
    """Subscribe to entity states and emit synthetic log lines."""
    _, entities, _ = await cli.device_info_and_list_entities()
    entity_info: dict[int, EntityInfo] = {e.key: e for e in entities}

    def on_state(state: EntityState) -> None:
        info = entity_info.get(state.key)
        text = format_state_log(state, info)
        if text is not None:
            msg = SubscribeLogsResponse()
            msg.level = LogLevel.LOG_LEVEL_DEBUG
            msg.message = text.encode("utf-8")
            on_log(msg)

    cli.subscribe_states(on_state)
