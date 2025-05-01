from phonenumber_field.modelfields import PhoneNumber

from messaging.providers.twilio import Twilio

SMS_SENDERS = {"265": "ConnectID", "258": "ConnectID", "232": "ConnectID"}


def send_sms(to: PhoneNumber, body: str):
    twilio = Twilio()
    twilio.send_sms(
        to.as_e164,
        body,
        sender=get_sms_sender(to.country_code),
    )


def get_sms_sender(country_code) -> str:
    return SMS_SENDERS.get(str(country_code))
