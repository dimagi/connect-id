import base64

from twilio.rest import Client

from django.conf import settings
from django.contrib.auth import authenticate
from django.http import HttpResponse

def send_sms(to, body):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        body=body,
        to=to,
        messaging_service_sid=settings.TWILIO_MESSAGING_SERVICE
    )


def get_ip(request):
    ip_address = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '127.0.0.1'))
    return ip_address.split(',')[0]

