from django.contrib.auth.models import AbstractUser
from django.db import models
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

    def generate_challenge(self):
        self.generate_token(valid_secs=600)
        message = f"Your verification token from commcare connect is {self.token}"
        if not self.phone_number.raw_input.startswith(TEST_NUMBER_PREFIX):
            sender = get_sms_sender(self.phone_number.country_code)
            send_sms(self.phone_number.as_e164, message, sender)
        return message

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['phone_number', 'user'], name='phone_number_user')
        ]


class RecoveryStatus(models.Model):
    class RecoverySteps(models.TextChoices):
        CONFIRM_PRIMARY = 'primary'
        CONFIRM_SECONDARY = 'secondary'
        RESET_PASSWORD = 'password'
        
    secret_key = models.TextField()
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE, unique=True)
    step = models.TextField(choices=RecoverySteps.choices)
