from __future__ import annotations

from typing import TYPE_CHECKING

from zeroconf import RecordUpdateListener
from zeroconf.const import _TYPE_A, _TYPE_AAAA, _TYPE_PTR

if TYPE_CHECKING:
    from zeroconf import RecordUpdate, Zeroconf

    from .reconnect_logic import ZeroconfWake


class ZeroconfRecordDispatcher(RecordUpdateListener):
    """Route record updates to the wakes registered for their names."""

    def __init__(self, zc: Zeroconf | None = None) -> None:
        self._zc = zc
        self._wakes: dict[str, list[ZeroconfWake]] = {}

    def add(self, wake: ZeroconfWake) -> None:
        """Route records named by the wake's keys to it."""
        for key in wake.keys:
            self._wakes.setdefault(key, []).append(wake)

    def remove(self, wake: ZeroconfWake) -> None:
        """Stop routing records to wake; the last one removes the listener."""
        for key in wake.keys:
            wakes = self._wakes[key]
            wakes.remove(wake)
            if not wakes:
                del self._wakes[key]
        if not self._wakes and self._zc is not None:
            del _dispatchers[id(self._zc)]
            self._zc.async_remove_listener(self)

    def async_update_records(
        self,
        zc: Zeroconf,  # noqa: ARG002 # pylint: disable=unused-argument
        now: float,
        records: list[RecordUpdate],
    ) -> None:
        _dispatch(self._wakes, now, records)


def _dispatch(wakes: dict, now: float, records: list) -> None:  # type: ignore[type-arg]
    """Hand each A/AAAA/PTR record named by a registered key to its wakes."""
    # Every mDNS packet on the LAN lands here, so the miss path must not
    # allocate; zeroconf pre-lowercases key and alias_key. `in (_TYPE_A,
    # _TYPE_AAAA)` would build a tuple per record in pure Python, while `==`
    # compiles to C int compares.
    for record_update in records:
        new_record = record_update.new
        record_type = new_record.type
        if record_type == _TYPE_A or record_type == _TYPE_AAAA:  # noqa: PLR1714, SIM109
            matched = wakes.get(new_record.key)
        elif record_type == _TYPE_PTR:
            matched = wakes.get(new_record.alias_key)
        else:
            continue
        if matched is not None:
            for wake in tuple(matched):
                wake.on_record(new_record, now)


_dispatchers: dict[int, ZeroconfRecordDispatcher] = {}


def async_add_wake(zc: Zeroconf, wake: ZeroconfWake) -> ZeroconfRecordDispatcher:
    """Register wake on the one shared listener for zc and return that listener."""
    if (dispatcher := _dispatchers.get(id(zc))) is None:
        dispatcher = ZeroconfRecordDispatcher(zc)
        zc.async_add_listener(dispatcher, None)
        _dispatchers[id(zc)] = dispatcher
    dispatcher.add(wake)
    return dispatcher
