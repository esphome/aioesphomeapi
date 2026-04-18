from __future__ import annotations

from typing import Any

from .api_pb2 import (  # type: ignore
    AlarmControlPanelStateResponse,
    BinarySensorStateResponse,
    ClimateStateResponse,
    CoverStateResponse,
    DateStateResponse,
    DateTimeStateResponse,
    EventResponse,
    FanStateResponse,
    LightStateResponse,
    ListEntitiesAlarmControlPanelResponse,
    ListEntitiesBinarySensorResponse,
    ListEntitiesButtonResponse,
    ListEntitiesCameraResponse,
    ListEntitiesClimateResponse,
    ListEntitiesCoverResponse,
    ListEntitiesDateResponse,
    ListEntitiesDateTimeResponse,
    ListEntitiesEventResponse,
    ListEntitiesFanResponse,
    ListEntitiesInfraredResponse,
    ListEntitiesLightResponse,
    ListEntitiesLockResponse,
    ListEntitiesMediaPlayerResponse,
    ListEntitiesNumberResponse,
    ListEntitiesSelectResponse,
    ListEntitiesSensorResponse,
    ListEntitiesServicesResponse,
    ListEntitiesSirenResponse,
    ListEntitiesSwitchResponse,
    ListEntitiesTextResponse,
    ListEntitiesTextSensorResponse,
    ListEntitiesTimeResponse,
    ListEntitiesUpdateResponse,
    ListEntitiesValveResponse,
    ListEntitiesWaterHeaterResponse,
    LockStateResponse,
    MediaPlayerStateResponse,
    NumberStateResponse,
    SelectStateResponse,
    SensorStateResponse,
    SirenStateResponse,
    SwitchStateResponse,
    TextSensorStateResponse,
    TextStateResponse,
    TimeStateResponse,
    UpdateStateResponse,
    ValveStateResponse,
    WaterHeaterStateResponse,
)
from .model import (
    AlarmControlPanelEntityState,
    AlarmControlPanelInfo,
    BinarySensorInfo,
    BinarySensorState,
    ButtonInfo,
    CameraInfo,
    CameraState,
    ClimateInfo,
    ClimateState,
    CoverInfo,
    CoverState,
    DateInfo,
    DateState,
    DateTimeInfo,
    DateTimeState,
    EntityInfo,
    EntityState,
    Event,
    EventInfo,
    FanInfo,
    FanState,
    InfraredInfo,
    LightInfo,
    LightState,
    LockEntityState,
    LockInfo,
    MediaPlayerEntityState,
    MediaPlayerInfo,
    NumberInfo,
    NumberState,
    SelectInfo,
    SelectState,
    SensorInfo,
    SensorState,
    SirenInfo,
    SirenState,
    SwitchInfo,
    SwitchState,
    TextInfo,
    TextSensorInfo,
    TextSensorState,
    TextState,
    TimeInfo,
    TimeState,
    UpdateInfo,
    UpdateState,
    ValveInfo,
    ValveState,
    WaterHeaterInfo,
    WaterHeaterState,
)

SUBSCRIBE_STATES_RESPONSE_TYPES: dict[Any, type[EntityState]] = {
    AlarmControlPanelStateResponse: AlarmControlPanelEntityState,
    BinarySensorStateResponse: BinarySensorState,
    ClimateStateResponse: ClimateState,
    CoverStateResponse: CoverState,
    DateStateResponse: DateState,
    DateTimeStateResponse: DateTimeState,
    EventResponse: Event,
    FanStateResponse: FanState,
    LightStateResponse: LightState,
    LockStateResponse: LockEntityState,
    MediaPlayerStateResponse: MediaPlayerEntityState,
    NumberStateResponse: NumberState,
    SelectStateResponse: SelectState,
    SensorStateResponse: SensorState,
    SirenStateResponse: SirenState,
    SwitchStateResponse: SwitchState,
    TextSensorStateResponse: TextSensorState,
    TextStateResponse: TextState,
    TimeStateResponse: TimeState,
    UpdateStateResponse: UpdateState,
    ValveStateResponse: ValveState,
    WaterHeaterStateResponse: WaterHeaterState,
}

LIST_ENTITIES_SERVICES_RESPONSE_TYPES: dict[Any, type[EntityInfo] | None] = {
    ListEntitiesAlarmControlPanelResponse: AlarmControlPanelInfo,
    ListEntitiesBinarySensorResponse: BinarySensorInfo,
    ListEntitiesButtonResponse: ButtonInfo,
    ListEntitiesCameraResponse: CameraInfo,
    ListEntitiesClimateResponse: ClimateInfo,
    ListEntitiesCoverResponse: CoverInfo,
    ListEntitiesDateResponse: DateInfo,
    ListEntitiesDateTimeResponse: DateTimeInfo,
    ListEntitiesEventResponse: EventInfo,
    ListEntitiesFanResponse: FanInfo,
    ListEntitiesInfraredResponse: InfraredInfo,
    ListEntitiesLightResponse: LightInfo,
    ListEntitiesLockResponse: LockInfo,
    ListEntitiesMediaPlayerResponse: MediaPlayerInfo,
    ListEntitiesNumberResponse: NumberInfo,
    ListEntitiesSelectResponse: SelectInfo,
    ListEntitiesSensorResponse: SensorInfo,
    ListEntitiesServicesResponse: None,
    ListEntitiesSirenResponse: SirenInfo,
    ListEntitiesSwitchResponse: SwitchInfo,
    ListEntitiesTextResponse: TextInfo,
    ListEntitiesTextSensorResponse: TextSensorInfo,
    ListEntitiesTimeResponse: TimeInfo,
    ListEntitiesUpdateResponse: UpdateInfo,
    ListEntitiesValveResponse: ValveInfo,
    ListEntitiesWaterHeaterResponse: WaterHeaterInfo,
}


def _build_state_type_to_info_type() -> dict[type[EntityState], type[EntityInfo]]:
    # Proto naming pairs each state response with a list-entities response by
    # a common stem: "{X}StateResponse" or "EventResponse" on the state side,
    # and "ListEntities{X}Response" on the info side.
    info_by_stem: dict[str, type[EntityInfo]] = {
        resp.__name__.removeprefix("ListEntities").removesuffix("Response"): info
        for resp, info in LIST_ENTITIES_SERVICES_RESPONSE_TYPES.items()
        if info is not None
    }
    mapping: dict[type[EntityState], type[EntityInfo]] = {
        state_cls: info_by_stem[
            resp.__name__.removesuffix("StateResponse").removesuffix("Response")
        ]
        for resp, state_cls in SUBSCRIBE_STATES_RESPONSE_TYPES.items()
    }
    # CameraState is derived from CameraImageResponse (not a subscribe-state
    # response), so it won't be picked up by the loop above.
    mapping[CameraState] = CameraInfo
    return mapping


STATE_TYPE_TO_INFO_TYPE: dict[type[EntityState], type[EntityInfo]] = (
    _build_state_type_to_info_type()
)
