import base64
from datetime import timedelta
import os

from uuid import uuid4

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser
from django.contrib.sites.models import Site
from django.db import models
from django.urls import reverse
from django.utils.timezone import now
from django_otp.models import SideChannelDevice

from django_otp.util import random_hex
from phonenumber_field.modelfields import PhoneNumberField

from utils import get_sms_sender, send_sms

from .const import TEST_NUMBER_PREFIX


class ConnectUser(AbstractUser):
    phone_number = PhoneNumberField()
    phone_validated = models.BooleanField(default=False)
    recovery_phone = PhoneNumberField(blank=True)
    recovery_phone_validated = models.BooleanField(default=False)
    name = models.TextField(max_length=150, blank=True)
    dob = models.DateField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    # this is effectively a password so use set_recovery_pin to
    # store a hashed value rather than setting it directly
    recovery_pin = models.CharField(null=True, blank=True, max_length=128)
    recovery_phone_validation_deadline = models.DateField(blank=True, null=True)
    deactivation_token = models.CharField(max_length=25, blank=True, null=True)
    deactivation_token_valid_until = models.DateTimeField(blank=True, null=True)

    # removed from base class
    first_name = None
    last_name = None

    REQUIRED_FIELDS = ["phone_number", "name"]

    def set_recovery_pin(self, pin):
        hashed_value = make_password(pin)
        self.recovery_pin = hashed_value

    def check_recovery_pin(self, pin):
        return check_password(pin, self.recovery_pin)

    def initiate_deactivation(self):
        self.deactivation_token = random_hex(7)
        self.deactivation_token_valid_until = now() + timedelta(seconds=600)
        self.save()
        message = (
            f"Your account deactivation request is pending. Please enter this token {self.deactivation_token} to confirm account deactivation."
            f"Warning: This action is irreversible. If you didn't request deactivation, please ignore this message. \n\n {settings.APP_HASH}"
        )
        if not self.phone_number.raw_input.startswith(TEST_NUMBER_PREFIX):
            sender = get_sms_sender(self.phone_number.country_code)
            send_sms(self.phone_number.as_e164, message, sender)
        return message

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["phone_number"],
                condition=models.Q(is_active=True),
                name="phone_number_active_user",
            )
        ]


class UserKey(models.Model):
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)
    key = models.CharField(max_length=60)
    valid = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)

    @classmethod
    def get_or_create_key_for_user(cls, user):
        user_key = cls.objects.filter(user=user, valid=True).first()
        if not user_key:
            user_key = UserKey(user=user)
            bin_key = os.urandom(32)
            user_key.key = base64.b64encode(bin_key).decode('utf-8')
        user_key.save()
        return user_key


class PhoneDevice(SideChannelDevice):
    phone_number = PhoneNumberField()
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)

    def generate_challenge(self):
        self.generate_token(valid_secs=600)
        message = f"Your verification token from commcare connect is {self.token} \n\n {settings.APP_HASH}"
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
        user_credential, created = cls.objects.get_or_create(user=user, credential=credential)
        if created:
            domain = Site.objects.get_current().domain
            location = reverse("accept_credential", args=(user_credential.invite_id,))
            url = f"https://{domain}{location}"
            message = (
                f"You have been given credential '{credential.name}'."
                f"Please click the following link to accept {url}"
            )
            sender = get_sms_sender(user.phone_number.country_code)
            send_sms(user.phone_number.as_e164, message, sender)
