import logging

from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


def send_email_otp_message(email: str, token: str, validity_minutes: int) -> None:
    masked = f"***@{email.split('@')[1]}"
    subject = "Your PersonalID verification code"
    body = f"Your email verification code is: {token}\nThis code expires in {validity_minutes} minutes."
    send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [email])
    logger.info("Email OTP sent to %s", masked)
