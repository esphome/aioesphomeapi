"""Tests for the state log formatter."""

from __future__ import annotations

from aioesphomeapi.model import (
    AlarmControlPanelEntityState,
    AlarmControlPanelState,
    BinarySensorInfo,
    BinarySensorState,
    CameraState,
    ClimateAction,
    ClimateFanMode,
    ClimateMode,
    ClimatePreset,
    ClimateState,
    ClimateSwingMode,
    CoverOperation,
    CoverState,
    DateState,
    Event,
    EventInfo,
    FanDirection,
    FanState,
    LightState,
    LockEntityState,
    LockState,
    MediaPlayerEntityState,
    MediaPlayerState,
    NumberState,
    SelectState,
    SensorInfo,
    SensorState,
    SwitchState,
    TextSensorState,
    TextState,
    TimeState,
    UpdateState,
    ValveOperation,
    ValveState,
    WaterHeaterMode,
    WaterHeaterState,
)
from aioesphomeapi.state_log_formatter import format_state_log


class TestFormatSensor:
    def test_basic(self) -> None:
        info = SensorInfo(
            name="CO2",
            key=1,
            unit_of_measurement="ppm",
            accuracy_decimals=0,
        )
        state = SensorState(key=1, state=420.0)
        result = format_state_log(state, info)
        assert result == "[S][sensor]: 'CO2' >> 420 ppm"

    def test_with_decimals(self) -> None:
        info = SensorInfo(
            name="Temperature",
            key=2,
            unit_of_measurement="°C",
            accuracy_decimals=2,
        )
        state = SensorState(key=2, state=35.63)
        result = format_state_log(state, info)
        assert result == "[S][sensor]: 'Temperature' >> 35.63 °C"

    def test_missing_state(self) -> None:
        info = SensorInfo(name="CO2", key=1, unit_of_measurement="ppm")
        state = SensorState(key=1, state=0.0, missing_state=True)
        assert format_state_log(state, info) is None

    def test_no_info(self) -> None:
        state = SensorState(key=1, state=42.0)
        result = format_state_log(state, None)
        assert result == "[S][sensor]: '?' >> 42.0"


class TestFormatBinarySensor:
    def test_on(self) -> None:
        info = BinarySensorInfo(name="Motion", key=1)
        state = BinarySensorState(key=1, state=True)
        assert format_state_log(state, info) == "[S][binary_sensor]: 'Motion' >> ON"

    def test_off(self) -> None:
        info = BinarySensorInfo(name="Motion", key=1)
        state = BinarySensorState(key=1, state=False)
        assert format_state_log(state, info) == "[S][binary_sensor]: 'Motion' >> OFF"

    def test_missing(self) -> None:
        info = BinarySensorInfo(name="Motion", key=1)
        state = BinarySensorState(key=1, state=False, missing_state=True)
        assert format_state_log(state, info) is None


class TestFormatSwitch:
    def test_on(self) -> None:
        state = SwitchState(key=1, state=True)
        info = BinarySensorInfo(name="Relay", key=1)
        assert format_state_log(state, info) == "[S][switch]: 'Relay' >> ON"

    def test_off(self) -> None:
        state = SwitchState(key=1, state=False)
        info = BinarySensorInfo(name="Relay", key=1)
        assert format_state_log(state, info) == "[S][switch]: 'Relay' >> OFF"


class TestFormatTextSensor:
    def test_basic(self) -> None:
        state = TextSensorState(key=1, state="2026.3.0")
        info = BinarySensorInfo(name="Version", key=1)
        assert (
            format_state_log(state, info) == "[S][text_sensor]: 'Version' >> '2026.3.0'"
        )

    def test_missing(self) -> None:
        state = TextSensorState(key=1, state="", missing_state=True)
        info = BinarySensorInfo(name="Version", key=1)
        assert format_state_log(state, info) is None


class TestFormatNumber:
    def test_basic(self) -> None:
        state = NumberState(key=1, state=50.0)
        info = BinarySensorInfo(name="Brightness", key=1)
        assert format_state_log(state, info) == "[S][number]: 'Brightness' >> 50.00"

    def test_missing(self) -> None:
        state = NumberState(key=1, state=0.0, missing_state=True)
        info = BinarySensorInfo(name="Brightness", key=1)
        assert format_state_log(state, info) is None


class TestFormatSelect:
    def test_basic(self) -> None:
        state = SelectState(key=1, state="eco")
        info = BinarySensorInfo(name="Mode", key=1)
        assert format_state_log(state, info) == "[S][select]: 'Mode' >> eco"

    def test_missing(self) -> None:
        state = SelectState(key=1, state="", missing_state=True)
        assert format_state_log(state, None) is None


class TestFormatLock:
    def test_locked(self) -> None:
        state = LockEntityState(key=1, state=LockState.LOCKED)
        info = BinarySensorInfo(name="Front Door", key=1)
        assert format_state_log(state, info) == "[S][lock]: 'Front Door' >> LOCKED"

    def test_unlocked(self) -> None:
        state = LockEntityState(key=1, state=LockState.UNLOCKED)
        info = BinarySensorInfo(name="Front Door", key=1)
        assert format_state_log(state, info) == "[S][lock]: 'Front Door' >> UNLOCKED"


class TestFormatEvent:
    def test_basic(self) -> None:
        state = Event(key=1, event_type="press")
        info = EventInfo(name="Button", key=1)
        assert format_state_log(state, info) == "[S][event]: 'Button' >> 'press'"


class TestFormatText:
    def test_basic(self) -> None:
        state = TextState(key=1, state="hello")
        info = BinarySensorInfo(name="Name", key=1)
        assert format_state_log(state, info) == "[S][text]: 'Name' >> 'hello'"

    def test_missing(self) -> None:
        state = TextState(key=1, state="", missing_state=True)
        assert format_state_log(state, None) is None


class TestFormatDate:
    def test_basic(self) -> None:
        state = DateState(key=1, year=2026, month=3, day=24)
        info = BinarySensorInfo(name="Birthday", key=1)
        assert format_state_log(state, info) == "[S][datetime]: 'Birthday' >> 2026-3-24"

    def test_missing(self) -> None:
        state = DateState(key=1, missing_state=True)
        assert format_state_log(state, None) is None


class TestFormatTime:
    def test_basic(self) -> None:
        state = TimeState(key=1, hour=7, minute=30, second=0)
        info = BinarySensorInfo(name="Alarm", key=1)
        assert format_state_log(state, info) == "[S][datetime]: 'Alarm' >> 07:30:00"

    def test_missing(self) -> None:
        state = TimeState(key=1, missing_state=True)
        assert format_state_log(state, None) is None


class TestFormatCover:
    def test_closed(self) -> None:
        state = CoverState(key=1, position=0.0, current_operation=CoverOperation.IDLE)
        info = BinarySensorInfo(name="Garage", key=1)
        result = format_state_log(state, info)
        assert result is not None
        lines = result.split("\n")
        assert lines[0] == "[S][cover]: 'Garage' >>"
        assert lines[1] == "[S][cover]:   State: CLOSED"
        assert lines[2] == "[S][cover]:   Current Operation: IDLE"

    def test_open(self) -> None:
        state = CoverState(key=1, position=1.0, current_operation=CoverOperation.IDLE)
        info = BinarySensorInfo(name="Garage", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][cover]:   State: OPEN" in result

    def test_partial(self) -> None:
        state = CoverState(
            key=1, position=0.5, current_operation=CoverOperation.IS_OPENING
        )
        info = BinarySensorInfo(name="Garage", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][cover]:   Position: 50%" in result
        assert "[S][cover]:   Current Operation: IS_OPENING" in result


class TestFormatValve:
    def test_closed(self) -> None:
        state = ValveState(key=1, position=0.0, current_operation=ValveOperation.IDLE)
        info = BinarySensorInfo(name="Water", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][valve]:   State: CLOSED" in result

    def test_open(self) -> None:
        state = ValveState(key=1, position=1.0, current_operation=ValveOperation.IDLE)
        info = BinarySensorInfo(name="Water", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][valve]:   State: OPEN" in result

    def test_partial(self) -> None:
        state = ValveState(
            key=1, position=0.75, current_operation=ValveOperation.IS_OPENING
        )
        info = BinarySensorInfo(name="Water", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][valve]:   Position: 75%" in result
        assert "[S][valve]:   Current Operation: IS_OPENING" in result


class TestFormatFan:
    def test_basic_on(self) -> None:
        state = FanState(key=1, state=True, speed_level=3)
        info = BinarySensorInfo(name="Fan", key=1)
        result = format_state_log(state, info)
        assert result is not None
        lines = result.split("\n")
        assert lines[0] == "[S][fan]: 'Fan' >> ON"
        assert lines[1] == "[S][fan]:   Speed: 3"

    def test_off(self) -> None:
        state = FanState(key=1, state=False)
        info = BinarySensorInfo(name="Fan", key=1)
        result = format_state_log(state, info)
        assert result == "[S][fan]: 'Fan' >> OFF"

    def test_with_oscillating_and_direction(self) -> None:
        state = FanState(
            key=1,
            state=True,
            oscillating=True,
            direction=FanDirection.REVERSE,
            preset_mode="turbo",
        )
        info = BinarySensorInfo(name="Fan", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][fan]:   Oscillating: YES" in result
        assert "[S][fan]:   Direction: REVERSE" in result
        assert "[S][fan]:   Preset Mode: turbo" in result


class TestFormatLight:
    def test_on_with_brightness(self) -> None:
        state = LightState(key=1, state=True, brightness=0.5)
        info = BinarySensorInfo(name="Light", key=1)
        result = format_state_log(state, info)
        assert result is not None
        lines = result.split("\n")
        assert lines[0] == "[S][light]: 'Light' >> ON"
        assert lines[1] == "[S][light]:   Brightness: 50%"

    def test_off(self) -> None:
        state = LightState(key=1, state=False)
        info = BinarySensorInfo(name="Light", key=1)
        result = format_state_log(state, info)
        assert result == "[S][light]: 'Light' >> OFF"

    def test_rgb(self) -> None:
        state = LightState(
            key=1, state=True, brightness=1.0, red=1.0, green=0.5, blue=0.0
        )
        info = BinarySensorInfo(name="RGB", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "Red: 100%, Green: 50%, Blue: 0%" in result

    def test_color_temperature_and_effect(self) -> None:
        state = LightState(
            key=1,
            state=True,
            brightness=0.8,
            color_temperature=250.0,
            effect="Rainbow",
        )
        info = BinarySensorInfo(name="Strip", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][light]:   Color temperature: 250.0 mireds" in result
        assert "[S][light]:   Effect: 'Rainbow'" in result


class TestFormatClimate:
    def test_basic(self) -> None:
        state = ClimateState(
            key=1,
            mode=ClimateMode.HEAT,
            current_temperature=20.5,
            target_temperature=22.0,
        )
        info = BinarySensorInfo(name="HVAC", key=1)
        result = format_state_log(state, info)
        assert result is not None
        lines = result.split("\n")
        assert lines[0] == "[S][climate]: 'HVAC' >>"
        assert lines[1] == "[S][climate]:   Mode: HEAT"
        assert "[S][climate]:   Current Temperature: 20.50°C" in result
        assert "[S][climate]:   Target Temperature: 22.00°C" in result

    def test_full_features(self) -> None:
        state = ClimateState(
            key=1,
            mode=ClimateMode.COOL,
            action=ClimateAction.COOLING,
            fan_mode=ClimateFanMode.HIGH,
            custom_fan_mode="turbo",
            preset=ClimatePreset.BOOST,
            custom_preset="my_preset",
            swing_mode=ClimateSwingMode.BOTH,
            current_temperature=25.0,
            target_temperature=20.0,
        )
        info = BinarySensorInfo(name="AC", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][climate]:   Action: COOLING" in result
        assert "[S][climate]:   Fan Mode: HIGH" in result
        assert "[S][climate]:   Custom Fan Mode: turbo" in result
        assert "[S][climate]:   Preset: BOOST" in result
        assert "[S][climate]:   Custom Preset: my_preset" in result
        assert "[S][climate]:   Swing Mode: BOTH" in result


class TestFormatAlarm:
    def test_disarmed(self) -> None:
        state = AlarmControlPanelEntityState(
            key=1, state=AlarmControlPanelState.DISARMED
        )
        info = BinarySensorInfo(name="Alarm", key=1)
        assert (
            format_state_log(state, info)
            == "[S][alarm_control_panel]: 'Alarm' >> DISARMED"
        )


class TestFormatMediaPlayer:
    def test_playing(self) -> None:
        state = MediaPlayerEntityState(
            key=1, state=MediaPlayerState.PLAYING, volume=0.75
        )
        info = BinarySensorInfo(name="Speaker", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][media_player]: 'Speaker' >> PLAYING" in result
        assert "[S][media_player]:   Volume: 75%" in result

    def test_idle(self) -> None:
        state = MediaPlayerEntityState(key=1, state=MediaPlayerState.IDLE)
        info = BinarySensorInfo(name="Speaker", key=1)
        result = format_state_log(state, info)
        assert result == "[S][media_player]: 'Speaker' >> IDLE"

    def test_muted(self) -> None:
        state = MediaPlayerEntityState(
            key=1, state=MediaPlayerState.PLAYING, volume=0.5, muted=True
        )
        info = BinarySensorInfo(name="Speaker", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][media_player]:   Muted: YES" in result


class TestFormatWaterHeater:
    def test_basic(self) -> None:
        state = WaterHeaterState(
            key=1,
            mode=WaterHeaterMode.ECO,
            current_temperature=45.0,
            target_temperature=50.0,
        )
        info = BinarySensorInfo(name="Boiler", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][water_heater]: 'Boiler' >>" in result
        assert "[S][water_heater]:   Mode: ECO" in result
        assert "[S][water_heater]:   Current Temperature: 45.00°C" in result


class TestFormatUpdate:
    def test_basic(self) -> None:
        state = UpdateState(
            key=1, current_version="2026.3.0", latest_version="2026.4.0"
        )
        info = BinarySensorInfo(name="Firmware", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][update]:   Current Version: 2026.3.0" in result
        assert "[S][update]:   Latest Version: 2026.4.0" in result

    def test_missing(self) -> None:
        state = UpdateState(key=1, missing_state=True)
        assert format_state_log(state, None) is None

    def test_with_progress(self) -> None:
        state = UpdateState(
            key=1,
            current_version="2026.3.0",
            latest_version="2026.4.0",
            has_progress=True,
            progress=75.0,
        )
        info = BinarySensorInfo(name="Firmware", key=1)
        result = format_state_log(state, info)
        assert result is not None
        assert "[S][update]:   Progress: 75%" in result


class TestFormatUnknownState:
    def test_camera_returns_none(self) -> None:
        state = CameraState(key=1)
        assert format_state_log(state, None) is None
