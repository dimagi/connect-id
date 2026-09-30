import logging

from sms.base import BaseSmsVendor, SendResult, SmsMessage

logger = logging.getLogger(__name__)


class ConsoleVendor(BaseSmsVendor):
    """Logs the message instead of sending it, so OTP codes can be read from the server log.

    Selected by ``send_sms`` when ``LOCAL_MODE`` is on.
    """

    name = "console"

    def _send(self, message: SmsMessage, sender: str | None) -> SendResult:
        logger.info("SMS to %s: %s", message.to.as_e164, message.body)
        return SendResult(vendor=self.name, vendor_message_id=None)
