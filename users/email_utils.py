import logging

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email

logger = logging.getLogger(__name__)


def send_email_otp_message(email: str, token: str, validity_minutes: int) -> None:
    try:
        validate_email(email)
    except ValidationError:
        logger.error("Invalid email address, skipping OTP send: %s", email)
        return
    local, domain = email.rsplit("@", 1)
    masked = f"{local[:1]}***@{domain}"
    subject = "Your PersonalID verification code"
    body = f"Your email verification code is: {token}\nThis code expires in {validity_minutes} minutes."
    send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [email])
    logger.info("Email OTP sent to %s", masked)


def mask_email(email: str) -> str | None:
    """Mask an address down to the first and last character of its local part.

    A local part of three characters or fewer is masked entirely.

    Returns None for an address we could not send an OTP to anyway, so callers treat it
    as no address at all rather than offering the user a mailbox that cannot be reached.
    """
    try:
        validate_email(email)
    except ValidationError:
        return None
    local, _, domain = email.rpartition("@")
    if len(local) <= 3:
        masked_local = "*" * len(local)
    else:
        masked_local = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    return f"{masked_local}@{domain}"
