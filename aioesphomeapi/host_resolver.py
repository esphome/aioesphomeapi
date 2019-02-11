import socket
import time

import zeroconf


class HostResolver(zeroconf.RecordUpdateListener):
    def __init__(self, name):
        self.name = name
        self.address = None

    def update_record(self, zc, now, record):
        if record is None:
            return
        if record.type == zeroconf._TYPE_A:
            assert isinstance(record, zeroconf.DNSAddress)
            if record.name == self.name:
                self.address = record.address

    def request(self, zc, timeout):
        now = time.time()
        delay = 0.2
        next_ = now + delay
        last = now + timeout

        try:
            zc.add_listener(self, zeroconf.DNSQuestion(self.name, zeroconf._TYPE_ANY,
                                                       zeroconf._CLASS_IN))
            while self.address is None:
                if last <= now:
                    # Timeout
                    return False
                if next_ <= now:
                    out = zeroconf.DNSOutgoing(zeroconf._FLAGS_QR_QUERY)
                    out.add_question(
                        zeroconf.DNSQuestion(self.name, zeroconf._TYPE_A, zeroconf._CLASS_IN))
                    out.add_answer_at_time(
                        zc.cache.get_by_details(self.name, zeroconf._TYPE_A,
                                                zeroconf._CLASS_IN), now)
                    zc.send(out)
                    next_ = now + delay
                    delay *= 2

                zc.wait(min(next_, last) - now)
                now = time.time()
        finally:
            zc.remove_listener(self)

        return True


def resolve_host(host, timeout=3.0):
    from aioesphomeapi import APIConnectionError

    try:
        zc = zeroconf.Zeroconf()
    except Exception:
        raise APIConnectionError("Cannot start mDNS sockets, is this a docker container without "
                                 "host network mode?")

    try:
        info = HostResolver(host + '.')
        address = None
        if info.request(zc, timeout):
            address = socket.inet_ntoa(info.address)
    except Exception as err:
        raise APIConnectionError("Error resolving mDNS hostname: {}".format(err))
    finally:
        zc.close()

    if address is None:
        raise APIConnectionError("Error resolving address with mDNS: Did not respond. "
                                 "Maybe the device is offline.")
    return address
