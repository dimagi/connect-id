import logging

from django.conf import settings
from phonenumber_field.phonenumber import PhoneNumber

from sms.base import SendResult, SmsCountryNotSupportedError, SmsMessage, SmsRateLimitedError, SmsSendError
from sms.limits import hit_country_limit, hit_number_limit, is_country_supported, mask
from sms.registry import get_vendor
from users.const import TEST_NUMBER_PREFIX

__all__ = [
    "SendResult",
    "SmsCountryNotSupportedError",
    "SmsMessage",
    "SmsRateLimitedError",
    "SmsSendError",
    "send_sms",
]

logger = logging.getLogger(__name__)


def send_sms(to: PhoneNumber, body: str) -> SendResult:
    if (to.raw_input or "").startswith(TEST_NUMBER_PREFIX):
        return SendResult(vendor=None, vendor_message_id=None, skipped=True)

    if not is_country_supported(to):
        logger.warning("SMS to %s blocked: country not supported", mask(to))
        raise SmsCountryNotSupportedError(to.country_code)

    exceeded = hit_number_limit(to) or hit_country_limit("sms", to)
    if exceeded:
        logger.warning("SMS to %s blocked: rate limited for %ss", mask(to), exceeded.retry_after_seconds)
        raise SmsRateLimitedError(exceeded.retry_after_seconds)

    # in future work the vendor will be determined based on the country code
    result = get_vendor(settings.SMS_DEFAULT_VENDOR).send(SmsMessage(to=to, body=body))
    logger.info("SMS sent to %s via %s, id %s", mask(to), result.vendor, result.vendor_message_id)
    return result
