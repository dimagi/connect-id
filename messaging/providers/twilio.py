from django.conf import settings
from twilio.rest import Client


class Twilio:
    client: Client

    def __init__(self):
        self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

    def send_sms(self, to, body, sender=None):
        self.client.messages.create(
            body=body, to=to, from_=sender, messaging_service_sid=settings.TWILIO_MESSAGING_SERVICE
        )
