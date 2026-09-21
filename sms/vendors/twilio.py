from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client

from sms.base import BaseSmsVendor, SendResult, SmsMessage


class TwilioVendor(BaseSmsVendor):
    name = "twilio"

    # Alphanumeric sender IDs registered with Twilio, by country calling code.
    SENDER_IDS = {"265": "ConnectID", "258": "ConnectID", "232": "ConnectID", "44": "ConnectID"}

    def __init__(self, account_sid: str, auth_token: str, messaging_service: str):
        self._client = Client(account_sid, auth_token)
        self._messaging_service = messaging_service

    def get_sender(self, message: SmsMessage) -> str | None:
        return self.SENDER_IDS.get(str(message.to.country_code))

    def error_code(self, exc: Exception) -> str | None:
        # Twilio omits the code on 5xx and transport-level failures.
        if isinstance(exc, TwilioRestException) and exc.code is not None:
            return str(exc.code)
        return None

    def _send(self, message: SmsMessage, sender: str | None) -> SendResult:
        sent = self._client.messages.create(
            body=message.body,
            to=message.to.as_e164,
            from_=sender,
            messaging_service_sid=self._messaging_service,
        )
        return SendResult(vendor=self.name, vendor_message_id=sent.sid)
