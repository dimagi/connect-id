from uuid import uuid4

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.urls import reverse
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
    # this is effectively a password so store use set_recovery_pin to
    # store a hashed value rather than setting it directly
    recovery_pin = models.CharField(null=True, blank=True, max_length=128)

    # removed from base class
    first_name = None
    last_name = None

    REQUIRED_FIELDS = ["phone_number", "name"]

    def set_recovery_pin(self, pin):
        hashed_value = make_password(pin)
        self.recovery_pin = hashed_value

    def check_recovery_pin(self, pin):
        return check_password(pin, self.recovery_pin)


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


class Credential(models.Model):
    name = models.CharField(max_length=300)
    slug = models.CharField(max_length=100)
    organization_slug = models.CharField(max_length=255)


class UserCredential(models.Model):
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)
    credential = models.ForeignKey(Credential, on_delete=models.CASCADE)
    accepted = models.BooleanField(default=False)
    invite_id = models.CharField(max_length=50, default=uuid4, unique=True)

    class Meta:
        unique_together = ("user", "credential")

    @classmethod
    def add_credential(cls, user, credential, request):
        user_credential = cls.objects.create(user=u, credential=credential)
        location = reverse("users:accept_credential", args=(user_credential.invite_id,))
        url = request.build_absolute_uri(location)
        message = (
            f"You have been given credential '{credential.name}'."
            "Please click the following link to accept "
        )
        sender = get_sms_sender(user.phone_number.country_code)
        send_sms(user.phone_number.as_e164, message, sender)
