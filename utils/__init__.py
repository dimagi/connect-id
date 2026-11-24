from rest_framework.throttling import AnonRateThrottle, ScopedRateThrottle, UserRateThrottle


def batched(items, size):
    for start in range(0, len(items), size):
        yield items[start : start + size]


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
