"""Which destination countries may receive SMS, and how many."""

from django.conf import settings
from phonenumber_field.phonenumber import PhoneNumber

from utils.rate_limit import Exceeded, Limit, hit, release

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
    """Count one `scope` event (e.g. "sms") for the number's country.

    Real users in the country are blocked until the window ends, so nearing and reaching the limit are
    reported to Sentry, once per window each.
    """
    return hit(
        f"{scope}:country:{number.country_code}",
        [
            _warned_limit(settings.PHONE_COUNTRY_HOURLY_LIMIT, HOUR),
            _warned_limit(settings.PHONE_COUNTRY_DAILY_LIMIT, DAY),
        ],
        log_fields={"scope": scope, "kind": "country", "country_code": number.country_code},
        report=True,
    )


def _warned_limit(max_count: int, window_seconds: int) -> Limit:
    """A limit that warns once its count reaches RATE_LIMIT_WARN_FRACTION of the maximum."""
    warn_at = int(max_count * settings.RATE_LIMIT_WARN_FRACTION)
    return Limit(max_count, window_seconds, warn_at=warn_at if 0 < warn_at < max_count else None)


def hit_user_otp_limit(user_id: int) -> Exceeded | None:
    """Count one OTP for the user, whichever of their numbers it goes to. A rejected OTP isn't counted."""
    log_fields = {"scope": "otp", "kind": "user", "user_id": user_id}
    exceeded = hit(f"otp:user:{user_id}", _user_otp_limits(), log_fields=log_fields)
    if exceeded:
        # A blocked OTP leaves the device's resend cooldown unchanged, so retries come straight back.
        # Counting them would let hourly rejections use up the daily limit.
        release_user_otp_limit(user_id)
    return exceeded


def release_user_otp_limit(user_id: int):
    """Take back an OTP counted by hit_user_otp_limit that was then not sent."""
    release(f"otp:user:{user_id}", _user_otp_limits())


def _user_otp_limits() -> list[Limit]:
    return [
        Limit(settings.OTP_USER_HOURLY_LIMIT, HOUR),
        Limit(settings.OTP_USER_DAILY_LIMIT, DAY),
    ]


def hit_number_limit(number: PhoneNumber) -> Exceeded | None:
    return hit(
        f"sms:number:{number.as_e164}",
        [
            Limit(settings.SMS_NUMBER_HOURLY_LIMIT, HOUR),
            Limit(settings.SMS_NUMBER_DAILY_LIMIT, DAY),
        ],
        log_fields={
            "scope": "sms",
            "kind": "number",
            "country_code": number.country_code,
            "number_ending": number.as_e164[-3:],
        },
    )
