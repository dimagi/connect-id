import ipaddress

from rest_framework.throttling import AnonRateThrottle, BaseThrottle, ScopedRateThrottle, UserRateThrottle


def batched(items, size):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def get_ip(request):
    """The client's address, found the same way the throttles find it (settings.NUM_PROXIES), or None."""
    address = BaseThrottle().get_ident(request)
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return None


class ConnectIDRateParser:
    def parse_rate(self, rate):
        if rate is None:
            return (None, None)
        num, period = rate.split("/")
        num_requests = int(num)
        duration = int(period)
        return (num_requests, duration)


class ConnectIDUserRateThrottle(ConnectIDRateParser, UserRateThrottle):
    pass


class ConnectIDAnonRateThrottle(ConnectIDRateParser, AnonRateThrottle):
    pass


class ConnectIDScopedRateThrottle(ConnectIDRateParser, ScopedRateThrottle):
    pass
