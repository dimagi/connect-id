from rest_framework.throttling import AnonRateThrottle, ScopedRateThrottle, UserRateThrottle


def get_ip(request):
    ip_address = request.headers.get("x-forwarded-for", request.headers.get("REMOTE_ADDR", "127.0.0.1"))
    return ip_address.split(",")[0]


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
