from __future__ import annotations

from typing import TYPE_CHECKING

from zeroconf import DNSAddress, DNSPointer, RecordUpdateListener  # type: ignore[attr-defined]
from zeroconf.const import _TYPE_PTR

if TYPE_CHECKING:
    from zeroconf import RecordUpdate, Zeroconf

    from .reconnect_logic import ZeroconfWake


class ZeroconfRecordDispatcher(RecordUpdateListener):
    """Route record updates to the wakes registered for their names."""

    def __init__(self, zc: Zeroconf) -> None:
        self.zc = zc
        self._wakes: dict[str, list[ZeroconfWake]] = {}

    def add(self, wake: ZeroconfWake) -> None:
        """Route records named by the wake's keys to it."""
        for key in wake.keys:
            self._wakes.setdefault(key, []).append(wake)

    def remove(self, wake: ZeroconfWake) -> bool:
        """Stop routing records to wake; True once no wakes are left."""
        for key in wake.keys:
            wakes = self._wakes[key]
            wakes.remove(wake)
            if not wakes:
                del self._wakes[key]
        return not self._wakes

    def async_update_records(
        self,
        zc: Zeroconf,  # noqa: ARG002 # pylint: disable=unused-argument
        now: float,
        records: list[RecordUpdate],
    ) -> None:
        _dispatch(self._wakes, now, records)


def _dispatch(wakes: dict, now: float, records: list) -> None:  # type: ignore[type-arg]
    """Hand each A/AAAA/PTR record named by a registered key to its wakes."""
    # Runs for every mDNS packet on the LAN; the miss path must not allocate.
    # zeroconf parses A/AAAA into exact DNSAddress and PTR/CNAME into exact
    # DNSPointer, and a class identity check is cheaper than reading .type.
    for record_update in records:
        new_record = record_update.new
        record_cls = type(new_record)
        if record_cls is DNSAddress:
            matched = wakes.get(new_record.key)
        elif record_cls is DNSPointer and new_record.type == _TYPE_PTR:
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


def async_remove_wake(dispatcher: ZeroconfRecordDispatcher, wake: ZeroconfWake) -> None:
    """Unregister wake; the shared listener goes away with the last wake."""
    if dispatcher.remove(wake):
        del _dispatchers[id(dispatcher.zc)]
        dispatcher.zc.async_remove_listener(dispatcher)
