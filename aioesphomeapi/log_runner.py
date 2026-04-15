from __future__ import annotations

from collections.abc import Callable, Coroutine
import logging
from typing import Any

from zeroconf.asyncio import AsyncZeroconf

from .api_pb2 import SubscribeLogsResponse  # type: ignore
from .client import APIClient
from .core import APIConnectionError
from .model import EntityInfo, EntityState, LogLevel
from .model_conversions import STATE_TYPE_TO_INFO_TYPE
from .reconnect_logic import ReconnectLogic
from .state_log_formatter import format_state_log

_LOGGER = logging.getLogger(__name__)

# Bright cyan (96) - a blue-green color between INFO (green/32) and DEBUG (cyan/36)
_STATE_COLOR = "\033[0;96m"
_ANSI_RESET = "\033[0m"


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
            log_callback = _StateLogProxy(on_log) if subscribe_states else None
            cli.subscribe_logs(
                log_callback.on_log if log_callback else on_log,
                log_level=log_level,
                dump_config=not dumped_config,
            )
            dumped_config = True
            if log_callback:
                await _subscribe_entity_states(cli, on_log, log_callback)
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


class _StateLogProxy:
    """Monitors firmware log messages to detect verbose logging.

    If a VERBOSE-level log message is seen, synthetic state lines
    are suppressed since the firmware is already sending them.
    """

    __slots__ = ("_on_log", "_seen_verbose")

    def __init__(self, on_log: Callable[[SubscribeLogsResponse], None]) -> None:
        self._on_log = on_log
        self._seen_verbose = False

    def on_log(self, msg: SubscribeLogsResponse) -> None:
        if not self._seen_verbose and msg.level >= LogLevel.LOG_LEVEL_VERBOSE:
            self._seen_verbose = True
        self._on_log(msg)

    @property
    def seen_verbose(self) -> bool:
        return self._seen_verbose


async def _subscribe_entity_states(
    cli: APIClient,
    on_log: Callable[[SubscribeLogsResponse], None],
    proxy: _StateLogProxy,
) -> None:
    """Subscribe to entity states and emit synthetic log lines.

    Automatically stops emitting synthetic state lines if a VERBOSE-level
    log message is received from the device, since that means the firmware
    is already sending the state publish logs itself.

    Skips the initial state dump on connect (first state per entity key)
    to avoid flooding the log with all current values.
    """
    _, entities, _ = await cli.device_info_and_list_entities()
    # Key by (info_type, device_id, key) so that two entities of different
    # types on the same device sharing an entity key hash (e.g. a climate
    # and a water_heater with the same name) don't overwrite each other.
    entity_info: dict[tuple[type[EntityInfo], int, int], EntityInfo] = {
        (type(e), e.device_id, e.key): e for e in entities
    }
    # Include type(state) so that two colliding entities each get their own
    # initial-dump skip; otherwise the second entity's first real state would
    # be swallowed as if it were the initial dump.
    seen_keys: set[tuple[type[EntityState], int, int]] = set()

    def on_state(state: EntityState) -> None:
        if proxy.seen_verbose:
            return
        state_id = (type(state), state.device_id, state.key)
        if state_id not in seen_keys:
            # Skip initial state dump on connect
            seen_keys.add(state_id)
            return
        info_type = STATE_TYPE_TO_INFO_TYPE.get(type(state))
        if info_type is None:
            _LOGGER.warning(
                "No EntityInfo type mapping for state %s; "
                "STATE_TYPE_TO_INFO_TYPE likely needs an entry",
                type(state).__name__,
            )
            info = None
        else:
            info = entity_info.get((info_type, state.device_id, state.key))
        text = format_state_log(state, info)
        if text is not None:
            msg = SubscribeLogsResponse()
            msg.level = LogLevel.LOG_LEVEL_DEBUG
            reset_color = f"{_ANSI_RESET}\n{_STATE_COLOR}"
            msg.message = (
                f"{_STATE_COLOR}{reset_color.join(text.split(chr(10)))}{_ANSI_RESET}"
            ).encode()
            on_log(msg)

    cli.subscribe_states(on_state)
