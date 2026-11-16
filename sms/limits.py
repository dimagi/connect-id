"""Which destination countries may receive SMS, and how many."""

import logging

from django.conf import settings
from phonenumber_field.phonenumber import PhoneNumber

from utils.rate_limit import Exceeded, Limit, hit

logger = logging.getLogger(__name__)

HOUR = 60 * 60
DAY = 24 * HOUR


def mask(number: PhoneNumber) -> str:
    if number.country_code is None:
        return "an unparseable number"
    return f"+{number.country_code} …{number.as_e164[-3:]}"


def is_country_supported(number: PhoneNumber) -> bool:
    # env.list keeps the spaces in "265, 258".
    supported = {code.strip() for code in settings.SMS_SUPPORTED_COUNTRY_CODES} - {""}
    return not supported or str(number.country_code) in supported


def hit_country_limit(scope: str, number: PhoneNumber) -> Exceeded | None:
    """Count one `scope` event (e.g. "sms") for the number's country, and report the limit once when it is hit."""
    exceeded = hit(
        f"{scope}:country:{number.country_code}",
        [
            Limit(settings.PHONE_COUNTRY_HOURLY_LIMIT, HOUR),
            Limit(settings.PHONE_COUNTRY_DAILY_LIMIT, DAY),
        ],
    )
    if exceeded and exceeded.is_first:
        # Error level so it reaches Sentry: real users in this country are blocked until the window ends.
        logger.error(
            "%s limit of %s per %ss reached for country code %s",
            scope,
            exceeded.limit.max_count,
            exceeded.limit.window_seconds,
            number.country_code,
        )
    return exceeded


def hit_user_otp_limit(user_id: int) -> Exceeded | None:
    """Count one OTP for the user, whichever of their numbers it goes to."""
    return hit(
        f"otp:user:{user_id}",
        [
            Limit(settings.OTP_USER_HOURLY_LIMIT, HOUR),
            Limit(settings.OTP_USER_DAILY_LIMIT, DAY),
        ],
        # A blocked OTP leaves the device's resend cooldown unchanged, so retries come straight back.
        count_rejected=False,
    )


def hit_number_limit(number: PhoneNumber) -> Exceeded | None:
    return hit(
        f"sms:number:{number.as_e164}",
        [
            Limit(settings.SMS_NUMBER_HOURLY_LIMIT, HOUR),
            Limit(settings.SMS_NUMBER_DAILY_LIMIT, DAY),
        ],
    )
