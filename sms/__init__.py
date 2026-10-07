from django.conf import settings
from phonenumber_field.phonenumber import PhoneNumber

from sms.base import SendResult, SmsMessage, SmsSendError
from sms.registry import get_vendor
from users.const import TEST_NUMBER_PREFIX

__all__ = ["SendResult", "SmsMessage", "SmsSendError", "send_sms"]


def send_sms(to: PhoneNumber, body: str) -> SendResult:
    if (to.raw_input or "").startswith(TEST_NUMBER_PREFIX):
        return SendResult(vendor=None, vendor_message_id=None, skipped=True)

    # in future work the vendor will be determined based on the country code
    return get_vendor(settings.SMS_DEFAULT_VENDOR).send(SmsMessage(to=to, body=body))
