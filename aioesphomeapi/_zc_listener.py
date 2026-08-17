from __future__ import annotations

from typing import TYPE_CHECKING

from zeroconf import RecordUpdateListener

if TYPE_CHECKING:
    from zeroconf import RecordUpdate, Zeroconf

    from .reconnect_logic import ZeroconfWake


class ReconnectRecordUpdateListener(RecordUpdateListener):
    """Forward zeroconf record updates to a ZeroconfWake.

    Lives in its own module so importing reconnect_logic does not import
    the zeroconf package; this module loads only when the mDNS-wake
    listener actually starts.
    """

    def __init__(self, wake: ZeroconfWake) -> None:
        self._wake = wake

    def async_update_records(
        self, zc: Zeroconf, now: float, records: list[RecordUpdate]
    ) -> None:
        self._wake.async_update_records(zc, now, records)
