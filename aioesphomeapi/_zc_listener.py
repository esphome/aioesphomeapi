from __future__ import annotations

from typing import TYPE_CHECKING

from zeroconf import RecordUpdateListener

if TYPE_CHECKING:
    from zeroconf import RecordUpdate, Zeroconf

    from .reconnect_logic import ReconnectLogic


class ReconnectRecordUpdateListener(RecordUpdateListener):
    """Forward zeroconf record updates to a ReconnectLogic.

    Lives in its own module so importing reconnect_logic does not import
    the zeroconf package; this module loads only when the mDNS-wake
    listener actually starts.
    """

    def __init__(self, logic: ReconnectLogic) -> None:
        self._logic = logic

    def async_update_records(
        self, zc: Zeroconf, now: float, records: list[RecordUpdate]
    ) -> None:
        self._logic.async_update_records(zc, now, records)
