import logging

from django.conf import settings
from twilio.rest import Client

logger = logging.getLogger(__name__)


def lookup_telecom_provider(phone_number):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    try:
        phone_info = client.lookups.v1.phone_numbers(phone_number).fetch(type="carrier")
        return phone_info.carrier.get("name")
    except Exception as e:
        logger.exception(
            "Error occurred during Twilio call for phone number %s: %s",
            phone_number,
            str(e),
        )
        return None
