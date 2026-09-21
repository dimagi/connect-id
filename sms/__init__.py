from phonenumber_field.phonenumber import PhoneNumber

from sms.base import SendResult, SmsMessage, SmsSendError
from sms.registry import DEFAULT_VENDOR, get_vendor
from users.const import TEST_NUMBER_PREFIX

__all__ = ["SendResult", "SmsMessage", "SmsSendError", "send_sms"]


def send_sms(to: PhoneNumber, body: str) -> SendResult:
    if (to.raw_input or "").startswith(TEST_NUMBER_PREFIX):
        return SendResult(vendor=None, vendor_message_id=None, skipped=True)

    vendor = DEFAULT_VENDOR  # in future work the vendor will be determined based on the country code
    return get_vendor(vendor).send(SmsMessage(to=to, body=body))
