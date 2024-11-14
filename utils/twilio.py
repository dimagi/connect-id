import logging

from twilio.rest import Client
from django.conf import settings


logger = logging.getLogger(__name__)

# Create the client instance only once
twilio_client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

def get_twilio_client():
    return twilio_client


def lookup_telecom_provider(phone_number):
    client = get_twilio_client()
    try:
        phone_info = client.lookups.v1.phone_numbers(phone_number).fetch(type="carrier")
        return phone_info.carrier.get("name")
    except Exception as e:
        logger.exception("Error occurred during twilio call: %s", str(e))
        return None
