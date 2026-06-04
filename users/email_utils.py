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
