from datetime import timedelta
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.timezone import now
from django_otp.models import SideChannelDevice

from phonenumber_field.modelfields import PhoneNumberField

from utils import get_sms_sender, send_sms

from .const import TEST_NUMBER_PREFIX

# Create your models here.


class ConnectUser(AbstractUser):
    phone_number = PhoneNumberField(unique=True)
    phone_validated = models.BooleanField(default=False)
    recovery_phone = PhoneNumberField(blank=True)
    recovery_phone_validated = models.BooleanField(default=False)
    name = models.TextField(max_length=150, blank=True)
    dob = models.DateField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)

    # removed from base class
    first_name = None
    last_name = None

    REQUIRED_FIELDS = ["phone_number", "name"]


class PhoneDevice(SideChannelDevice):
    phone_number = PhoneNumberField()
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)
    otp_last_sent = models.DateTimeField(null=True, blank=True)

    def generate_challenge(self):
        # generate and send new token if the old token is valid for less than 5 minutes
        # set he otp_last_sent to None to send the new OTP immediately
        if self.valid_until - now() <= timedelta(minutes=5):
            self.otp_last_sent = None
            self.generate_token(valid_secs=600)
        message = f"Your verification token from commcare connect is {self.token}"
        # send the OTP if last sent message is not within the last 2 minutes
        if self.otp_last_sent is None or (
            self.otp_last_sent and now() - self.otp_last_sent >= timedelta(minutes=2)
        ):
            if not self.phone_number.raw_input.startswith(TEST_NUMBER_PREFIX):
                sender = get_sms_sender(self.phone_number.country_code)
                send_sms(self.phone_number.as_e164, message, sender)
            self.otp_last_sent = now()
            self.save()
        return message

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["phone_number", "user"], name="phone_number_user"
            )
        ]


class RecoveryStatus(models.Model):
    class RecoverySteps(models.TextChoices):
        CONFIRM_PRIMARY = "primary"
        CONFIRM_SECONDARY = "secondary"
        RESET_PASSWORD = "password"

    secret_key = models.TextField()
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE, unique=True)
    step = models.TextField(choices=RecoverySteps.choices)
