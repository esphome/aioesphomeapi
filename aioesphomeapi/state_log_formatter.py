"""Format entity state changes as log lines for display in log viewers."""

from __future__ import annotations

from collections.abc import Callable
from math import isnan
from typing import TYPE_CHECKING

from .model import (
    AlarmControlPanelEntityState,
    BinarySensorState,
    ClimateAction,
    ClimatePreset,
    ClimateState,
    ClimateSwingMode,
    CoverState,
    DateState,
    Event,
    FanDirection,
    FanState,
    LightState,
    LockEntityState,
    MediaPlayerEntityState,
    NumberState,
    SelectState,
    SensorInfo,
    SensorState,
    SwitchState,
    TextSensorState,
    TextState,
    TimeState,
    UpdateState,
    ValveState,
    WaterHeaterState,
)

if TYPE_CHECKING:
    from .model import EntityInfo, EntityState


def _name(info: EntityInfo | None) -> str:
    return info.name if info else "?"


def _on_off(value: bool) -> str:
    return "ON" if value else "OFF"


def _enum_name(value: object) -> str:
    return value.name if value is not None else "UNKNOWN"  # type: ignore[attr-defined]


def _header(tag: str, info: EntityInfo | None, value: str) -> str:
    return f"[S][{tag}]: '{_name(info)}' >> {value}"


def _detail(tag: str, key: str, value: object) -> str:
    return f"[S][{tag}]:   {key}: {value}"


def _position_lines(tag: str, position: float, operation: object) -> list[str]:
    """Format position/state and operation for cover/valve."""
    parts: list[str] = []
    if position == 0.0:
        parts.append(f"[S][{tag}]:   State: CLOSED")
    elif position == 1.0:
        parts.append(f"[S][{tag}]:   State: OPEN")
    else:
        parts.append(f"[S][{tag}]:   Position: {position * 100.0:.0f}%")
    if operation is not None:
        parts.append(_detail(tag, "Current Operation", operation.name))  # type: ignore[attr-defined]
    return parts


def _format_sensor(state: SensorState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = _name(info)
    if info is not None and isinstance(info, SensorInfo):
        decimals = max(0, info.accuracy_decimals)
        unit = info.unit_of_measurement
        return f"[S][sensor]: '{name}' >> {state.state:.{decimals}f} {unit}"
    return f"[S][sensor]: '{name}' >> {state.state}"


def _format_binary_sensor(
    state: BinarySensorState, info: EntityInfo | None
) -> str | None:
    if state.missing_state:
        return None
    return _header("binary_sensor", info, _on_off(state.state))


def _format_switch(state: SwitchState, info: EntityInfo | None) -> str | None:
    return _header("switch", info, _on_off(state.state))


def _format_text_sensor(state: TextSensorState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    return _header("text_sensor", info, f"'{state.state}'")


def _format_number(state: NumberState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    return _header("number", info, f"{state.state:.2f}")


def _format_select(state: SelectState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    return _header("select", info, state.state)


def _format_lock(state: LockEntityState, info: EntityInfo | None) -> str | None:
    return _header("lock", info, _enum_name(state.state))


def _format_event(state: Event, info: EntityInfo | None) -> str | None:
    return _header("event", info, f"'{state.event_type}'")


def _format_text(state: TextState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    return _header("text", info, f"'{state.state}'")


def _format_date(state: DateState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    return _header("datetime", info, f"{state.year}-{state.month}-{state.day}")


def _format_time(state: TimeState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    return _header(
        "datetime", info, f"{state.hour:02d}:{state.minute:02d}:{state.second:02d}"
    )


def _format_cover(state: CoverState, info: EntityInfo | None) -> str | None:
    tag = "cover"
    parts = [
        f"[S][{tag}]: '{_name(info)}' >>",
        *_position_lines(tag, state.position, state.current_operation),
    ]
    return "\n".join(parts)


def _format_valve(state: ValveState, info: EntityInfo | None) -> str | None:
    tag = "valve"
    parts = [
        f"[S][{tag}]: '{_name(info)}' >>",
        *_position_lines(tag, state.position, state.current_operation),
    ]
    return "\n".join(parts)


def _format_fan(state: FanState, info: EntityInfo | None) -> str | None:
    tag = "fan"
    parts = [_header(tag, info, _on_off(state.state))]
    if state.speed_level:
        parts.append(_detail(tag, "Speed", state.speed_level))
    if state.oscillating:
        parts.append(_detail(tag, "Oscillating", "YES"))
    if state.direction is not None and state.direction != FanDirection.FORWARD:
        parts.append(_detail(tag, "Direction", state.direction.name))
    if state.preset_mode:
        parts.append(_detail(tag, "Preset Mode", state.preset_mode))
    return "\n".join(parts)


def _format_light(state: LightState, info: EntityInfo | None) -> str | None:
    tag = "light"
    parts = [_header(tag, info, _on_off(state.state))]
    if state.state:
        if state.brightness:
            parts.append(_detail(tag, "Brightness", f"{state.brightness * 100.0:.0f}%"))
        if state.red or state.green or state.blue:
            parts.append(
                _detail(
                    tag,
                    "Red",
                    f"{state.red * 100.0:.0f}%, "
                    f"Green: {state.green * 100.0:.0f}%, "
                    f"Blue: {state.blue * 100.0:.0f}%",
                )
            )
        if state.color_temperature:
            parts.append(
                _detail(
                    tag, "Color temperature", f"{state.color_temperature:.1f} mireds"
                )
            )
        if state.effect:
            parts.append(_detail(tag, "Effect", f"'{state.effect}'"))
    return "\n".join(parts)


def _format_climate(state: ClimateState, info: EntityInfo | None) -> str | None:
    tag = "climate"
    parts = [
        f"[S][{tag}]: '{_name(info)}' >>",
        _detail(tag, "Mode", _enum_name(state.mode)),
    ]
    if state.action is not None and state.action != ClimateAction.OFF:
        parts.append(_detail(tag, "Action", state.action.name))
    if state.fan_mode is not None:
        parts.append(_detail(tag, "Fan Mode", state.fan_mode.name))
    if state.custom_fan_mode:
        parts.append(_detail(tag, "Custom Fan Mode", state.custom_fan_mode))
    if state.preset is not None and state.preset != ClimatePreset.NONE:
        parts.append(_detail(tag, "Preset", state.preset.name))
    if state.custom_preset:
        parts.append(_detail(tag, "Custom Preset", state.custom_preset))
    if state.swing_mode is not None and state.swing_mode != ClimateSwingMode.OFF:
        parts.append(_detail(tag, "Swing Mode", state.swing_mode.name))
    ct = state.current_temperature
    if not isnan(ct):
        parts.append(_detail(tag, "Current Temperature", f"{ct:.2f}°C"))
    tt = state.target_temperature
    if not isnan(tt):
        parts.append(_detail(tag, "Target Temperature", f"{tt:.2f}°C"))
    return "\n".join(parts)


def _format_alarm(
    state: AlarmControlPanelEntityState, info: EntityInfo | None
) -> str | None:
    return _header("alarm_control_panel", info, _enum_name(state.state))


def _format_media_player(
    state: MediaPlayerEntityState, info: EntityInfo | None
) -> str | None:
    tag = "media_player"
    parts = [_header(tag, info, _enum_name(state.state))]
    if state.volume:
        parts.append(_detail(tag, "Volume", f"{state.volume * 100.0:.0f}%"))
    if state.muted:
        parts.append(_detail(tag, "Muted", "YES"))
    return "\n".join(parts)


def _format_water_heater(
    state: WaterHeaterState, info: EntityInfo | None
) -> str | None:
    tag = "water_heater"
    parts = [
        f"[S][{tag}]: '{_name(info)}' >>",
        _detail(tag, "Mode", _enum_name(state.mode)),
    ]
    ct = state.current_temperature
    if not isnan(ct):
        parts.append(_detail(tag, "Current Temperature", f"{ct:.2f}°C"))
    tt = state.target_temperature
    if not isnan(tt):
        parts.append(_detail(tag, "Target Temperature", f"{tt:.2f}°C"))
    return "\n".join(parts)


def _format_update(state: UpdateState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    tag = "update"
    parts = [
        f"[S][{tag}]: '{_name(info)}' >>",
        _detail(tag, "Current Version", state.current_version),
    ]
    if state.latest_version:
        parts.append(_detail(tag, "Latest Version", state.latest_version))
    if state.has_progress:
        parts.append(_detail(tag, "Progress", f"{state.progress:.0f}%"))
    return "\n".join(parts)


# Dispatch table: state type -> formatter function
_STATE_FORMATTERS: dict[type, Callable[..., str | None]] = {
    SensorState: _format_sensor,
    BinarySensorState: _format_binary_sensor,
    SwitchState: _format_switch,
    TextSensorState: _format_text_sensor,
    NumberState: _format_number,
    SelectState: _format_select,
    LockEntityState: _format_lock,
    Event: _format_event,
    TextState: _format_text,
    DateState: _format_date,
    TimeState: _format_time,
    CoverState: _format_cover,
    ValveState: _format_valve,
    FanState: _format_fan,
    LightState: _format_light,
    ClimateState: _format_climate,
    AlarmControlPanelEntityState: _format_alarm,
    MediaPlayerEntityState: _format_media_player,
    WaterHeaterState: _format_water_heater,
    UpdateState: _format_update,
}


def format_state_log(
    state: EntityState,
    info: EntityInfo | None,
) -> str | None:
    """Format an entity state change as a log line.

    Returns the formatted log text including [S][tag]: prefix,
    or None if the state should not be logged.
    """
    formatter = _STATE_FORMATTERS.get(type(state))
    if formatter is None:
        return None
    return formatter(state, info)
