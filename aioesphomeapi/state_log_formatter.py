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


def _on_off(value: bool) -> str:
    return "ON" if value else "OFF"


def _format_sensor(state: SensorState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = info.name if info else "?"
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
    name = info.name if info else "?"
    return f"[S][binary_sensor]: '{name}' >> {_on_off(state.state)}"


def _format_switch(state: SwitchState, info: EntityInfo | None) -> str | None:
    name = info.name if info else "?"
    return f"[S][switch]: '{name}' >> {_on_off(state.state)}"


def _format_text_sensor(state: TextSensorState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = info.name if info else "?"
    return f"[S][text_sensor]: '{name}' >> '{state.state}'"


def _format_number(state: NumberState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = info.name if info else "?"
    return f"[S][number]: '{name}' >> {state.state:.2f}"


def _format_select(state: SelectState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = info.name if info else "?"
    return f"[S][select]: '{name}' >> {state.state}"


def _format_lock(state: LockEntityState, info: EntityInfo | None) -> str | None:
    name = info.name if info else "?"
    lock_state = state.state
    state_str = lock_state.name if lock_state is not None else "UNKNOWN"
    return f"[S][lock]: '{name}' >> {state_str}"


def _format_event(state: Event, info: EntityInfo | None) -> str | None:
    name = info.name if info else "?"
    return f"[S][event]: '{name}' >> '{state.event_type}'"


def _format_text(state: TextState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = info.name if info else "?"
    return f"[S][text]: '{name}' >> '{state.state}'"


def _format_date(state: DateState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = info.name if info else "?"
    return f"[S][datetime]: '{name}' >> {state.year}-{state.month}-{state.day}"


def _format_time(state: TimeState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = info.name if info else "?"
    return (
        f"[S][datetime]: '{name}' >> "
        f"{state.hour:02d}:{state.minute:02d}:{state.second:02d}"
    )


def _format_cover(state: CoverState, info: EntityInfo | None) -> str | None:
    name = info.name if info else "?"
    parts = [f"[S][cover]: '{name}' >>"]
    pos = state.position
    if pos == 0.0:
        parts.append("[S][cover]:   State: CLOSED")
    elif pos == 1.0:
        parts.append("[S][cover]:   State: OPEN")
    else:
        parts.append(f"[S][cover]:   Position: {pos * 100.0:.0f}%")
    op = state.current_operation
    if op is not None:
        parts.append(f"[S][cover]:   Current Operation: {op.name}")
    return "\n".join(parts)


def _format_valve(state: ValveState, info: EntityInfo | None) -> str | None:
    name = info.name if info else "?"
    parts = [f"[S][valve]: '{name}' >>"]
    pos = state.position
    if pos == 0.0:
        parts.append("[S][valve]:   State: CLOSED")
    elif pos == 1.0:
        parts.append("[S][valve]:   State: OPEN")
    else:
        parts.append(f"[S][valve]:   Position: {pos * 100.0:.0f}%")
    op = state.current_operation
    if op is not None:
        parts.append(f"[S][valve]:   Current Operation: {op.name}")
    return "\n".join(parts)


def _format_fan(state: FanState, info: EntityInfo | None) -> str | None:
    name = info.name if info else "?"
    parts = [f"[S][fan]: '{name}' >> {_on_off(state.state)}"]
    if state.speed_level:
        parts.append(f"[S][fan]:   Speed: {state.speed_level}")
    if state.oscillating:
        parts.append("[S][fan]:   Oscillating: YES")
    if state.direction is not None and state.direction != FanDirection.FORWARD:
        parts.append(f"[S][fan]:   Direction: {state.direction.name}")
    if state.preset_mode:
        parts.append(f"[S][fan]:   Preset Mode: {state.preset_mode}")
    return "\n".join(parts)


def _format_light(state: LightState, info: EntityInfo | None) -> str | None:
    name = info.name if info else "?"
    parts = [f"[S][light]: '{name}' >> {_on_off(state.state)}"]
    if state.state:
        if state.brightness:
            parts.append(f"[S][light]:   Brightness: {state.brightness * 100.0:.0f}%")
        if state.red or state.green or state.blue:
            parts.append(
                f"[S][light]:   Red: {state.red * 100.0:.0f}%, "
                f"Green: {state.green * 100.0:.0f}%, "
                f"Blue: {state.blue * 100.0:.0f}%"
            )
        if state.color_temperature:
            parts.append(
                f"[S][light]:   Color temperature: {state.color_temperature:.1f} mireds"
            )
        if state.effect:
            parts.append(f"[S][light]:   Effect: '{state.effect}'")
    return "\n".join(parts)


def _format_climate(state: ClimateState, info: EntityInfo | None) -> str | None:
    name = info.name if info else "?"
    mode = state.mode
    mode_str = mode.name if mode is not None else "UNKNOWN"
    parts = [f"[S][climate]: '{name}' >>", f"[S][climate]:   Mode: {mode_str}"]
    action = state.action
    if action is not None and action != ClimateAction.OFF:
        parts.append(f"[S][climate]:   Action: {action.name}")
    fan = state.fan_mode
    if fan is not None:
        parts.append(f"[S][climate]:   Fan Mode: {fan.name}")
    if state.custom_fan_mode:
        parts.append(f"[S][climate]:   Custom Fan Mode: {state.custom_fan_mode}")
    preset = state.preset
    if preset is not None and preset != ClimatePreset.NONE:
        parts.append(f"[S][climate]:   Preset: {preset.name}")
    if state.custom_preset:
        parts.append(f"[S][climate]:   Custom Preset: {state.custom_preset}")
    swing = state.swing_mode
    if swing is not None and swing != ClimateSwingMode.OFF:
        parts.append(f"[S][climate]:   Swing Mode: {swing.name}")
    ct = state.current_temperature
    if not isnan(ct):
        parts.append(f"[S][climate]:   Current Temperature: {ct:.2f}°C")
    tt = state.target_temperature
    if not isnan(tt):
        parts.append(f"[S][climate]:   Target Temperature: {tt:.2f}°C")
    return "\n".join(parts)


def _format_alarm(
    state: AlarmControlPanelEntityState, info: EntityInfo | None
) -> str | None:
    name = info.name if info else "?"
    alarm_state = state.state
    state_str = alarm_state.name if alarm_state is not None else "UNKNOWN"
    return f"[S][alarm_control_panel]: '{name}' >> {state_str}"


def _format_water_heater(
    state: WaterHeaterState, info: EntityInfo | None
) -> str | None:
    name = info.name if info else "?"
    mode = state.mode
    mode_str = mode.name if mode is not None else "UNKNOWN"
    parts = [
        f"[S][water_heater]: '{name}' >>",
        f"[S][water_heater]:   Mode: {mode_str}",
    ]
    ct = state.current_temperature
    if not isnan(ct):
        parts.append(f"[S][water_heater]:   Current Temperature: {ct:.2f}°C")
    tt = state.target_temperature
    if not isnan(tt):
        parts.append(f"[S][water_heater]:   Target Temperature: {tt:.2f}°C")
    return "\n".join(parts)


def _format_update(state: UpdateState, info: EntityInfo | None) -> str | None:
    if state.missing_state:
        return None
    name = info.name if info else "?"
    parts = [
        f"[S][update]: '{name}' >>",
        f"[S][update]:   Current Version: {state.current_version}",
    ]
    if state.latest_version:
        parts.append(f"[S][update]:   Latest Version: {state.latest_version}")
    if state.has_progress:
        parts.append(f"[S][update]:   Progress: {state.progress:.0f}%")
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
