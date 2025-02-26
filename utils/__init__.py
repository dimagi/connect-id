from django.conf import settings
from rest_framework.throttling import AnonRateThrottle, ScopedRateThrottle, UserRateThrottle
from twilio.rest import Client


def send_sms(to, body, sender=None):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    client.messages.create(body=body, to=to, from_=sender, messaging_service_sid=settings.TWILIO_MESSAGING_SERVICE)


def get_ip(request):
    ip_address = request.headers.get("x-forwarded-for", request.headers.get("REMOTE_ADDR", "127.0.0.1"))
    return ip_address.split(",")[0]


def get_sms_sender(country_code):
    SMS_SENDERS = {"265": "ConnectID", "258": "ConnectID"}
    return SMS_SENDERS.get(str(country_code))


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
