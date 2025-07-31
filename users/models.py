import base64
import os
from datetime import timedelta
from secrets import token_hex
from uuid import uuid4

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser, AnonymousUser
from django.contrib.sites.models import Site
from django.db import models
from django.urls import reverse
from django.utils.timezone import now
from django_otp.models import SideChannelDevice
from django_otp.util import random_hex
from geopy.geocoders import Nominatim
from oauth2_provider.generators import generate_client_id, generate_client_secret
from phonenumber_field.modelfields import PhoneNumberField

from users.exceptions import RecoveryPinNotSetError
from users.services import get_user_photo_base64
from utils import get_sms_sender, send_sms

from .const import MAX_BACKUP_CODE_ATTEMPTS, TEST_NUMBER_PREFIX


class ConnectUser(AbstractUser):
    class DeviceSecurity(models.TextChoices):
        PIN = "pin", "pin"
        BIOMETRIC = "biometric", "biometric"

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

    device_security = models.CharField(choices=DeviceSecurity.choices, default=DeviceSecurity.BIOMETRIC, max_length=15)
    is_locked = models.BooleanField(default=False)
    failed_backup_code_attempts = models.IntegerField(default=0)

    # removed from base class
    first_name = None
    last_name = None

    REQUIRED_FIELDS = ["phone_number", "name"]

    @classmethod
    def get_device_security_requirement(cls, phone_number, invited_user=False) -> str:
        try:
            user = cls.objects.get(phone_number=phone_number, is_active=True)
        except ConnectUser.DoesNotExist:
            if invited_user:
                return ConnectUser.DeviceSecurity.PIN.value
            else:
                return ConnectUser.DeviceSecurity.BIOMETRIC.value
        return user.device_security

    def set_recovery_pin(self, pin):
        hashed_value = make_password(pin)
        self.recovery_pin = hashed_value

    def check_recovery_pin(self, pin):
        if not self.recovery_pin:
            raise RecoveryPinNotSetError("Recovery pin is not set")
        return check_password(pin, self.recovery_pin)

    def initiate_deactivation(self):
        self.deactivation_token = random_hex(7)
        self.deactivation_token_valid_until = now() + timedelta(seconds=600)
        self.save()
        message = (
            f"Your account deactivation request is pending. Please enter this token {self.deactivation_token} "
            f"to confirm account deactivation."
            f"Warning: This action is irreversible. If you didn't request deactivation, "
            f"please ignore this message. \n\n {settings.APP_HASH}"
        )
        if not self.phone_number.raw_input.startswith(TEST_NUMBER_PREFIX):
            sender = get_sms_sender(self.phone_number.country_code)
            send_sms(self.phone_number.as_e164, message, sender)
        return message

    def get_photo(self):
        return get_user_photo_base64(self.username)

    def add_failed_backup_code_attempt(self):
        self.failed_backup_code_attempts += 1
        self.save()

    def reset_failed_backup_code_attempts(self):
        self.failed_backup_code_attempts = 0

    @property
    def backup_code_attempts_left(self):
        return max(MAX_BACKUP_CODE_ATTEMPTS - self.failed_backup_code_attempts, 0)

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
            user_key.key = base64.b64encode(bin_key).decode("utf-8")
        user_key.save()
        return user_key


class BasePhoneDevice(SideChannelDevice):
    phone_number = PhoneNumberField()
    otp_last_sent = models.DateTimeField(null=True, blank=True)
    attempts = models.IntegerField(default=1)

    class Meta:
        abstract = True

    def generate_challenge(self):
        # generate and send new token if the old token is valid for less than 5 minutes
        # set he otp_last_sent to None to send the new OTP immediately
        if self.valid_until - now() <= timedelta(minutes=5):
            self.otp_last_sent = None
            self.generate_token(valid_secs=1800)
            self.attempts = 0
        message = f"Your verification token from commcare connect is {self.token} \n\n {settings.APP_HASH}"
        # backoff attempts exponentially
        wait_time = 2**self.attempts
        if self.otp_last_sent is None or (
            self.otp_last_sent and now() - self.otp_last_sent >= timedelta(minutes=wait_time)
        ):
            if not self.phone_number.raw_input.startswith(TEST_NUMBER_PREFIX):
                sender = get_sms_sender(self.phone_number.country_code)
                send_sms(self.phone_number.as_e164, message, sender)
            self.otp_last_sent = now()
            self.attempts += 1
            self.save()

        return message


class PhoneDevice(BasePhoneDevice):
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["phone_number", "user"], name="phone_number_user")]


class RecoveryStatus(models.Model):
    class RecoverySteps(models.TextChoices):
        CONFIRM_PRIMARY = "primary"
        CONFIRM_SECONDARY = "secondary"
        RESET_PASSWORD = "password"

    secret_key = models.TextField()
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE, unique=True)
    step = models.TextField(choices=RecoverySteps.choices)


class ServerKeys(models.Model):
    name = models.CharField(max_length=255)
    client_id = models.CharField(max_length=100, unique=True, db_index=True, default=generate_client_id)
    secret_key = models.CharField(max_length=255, default=generate_client_secret)

    def __str__(self):
        return self.name


class IssuingAuthority(models.Model):
    class IssuingAuthorityTypes(models.TextChoices):
        CONNECT = "CONNECT", "CONNECT"
        HQ = "HQ", "HQ"

    class IssuingAuthorityEnvironments(models.TextChoices):
        PRODUCTION = "production", "production"
        STAGING = "staging", "staging"
        INDIA = "india", "india"

    issuing_authority = models.CharField(max_length=50, choices=IssuingAuthorityTypes.choices)
    issuer_environment = models.CharField(max_length=50, choices=IssuingAuthorityEnvironments.choices)
    server_credentials = models.ForeignKey(ServerKeys, on_delete=models.PROTECT)

    class Meta:
        verbose_name = "Issuing Authority"
        verbose_name_plural = "Issuing Authorities"


class Credential(models.Model):
    class CredentialTypes(models.TextChoices):
        APP_ACTIVITY = "APP_ACTIVITY", "APP_ACTIVITY"
        LEARN = "LEARN", "LEARN"
        DELIVER = "DELIVER", "DELIVER"

    uuid = models.UUIDField(default=uuid4)
    title = models.CharField(max_length=300)
    issuer = models.ForeignKey(IssuingAuthority, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    level = models.CharField(max_length=50)  # credential level/code (e.g. 3_MONTHS_ACTIVE)
    type = models.CharField(max_length=50, choices=CredentialTypes.choices)
    app_id = models.CharField(max_length=50, blank=True, null=True)
    opportunity_id = models.CharField(max_length=50, blank=True, null=True)
    slug = models.CharField(max_length=50)

    class Meta:
        unique_together = ("issuer", "level", "type", "slug")


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
                f"You have been given credential '{credential.title}'."
                f"Please click the following link to accept {url}"
            )
            sender = get_sms_sender(user.phone_number.country_code)
            send_sms(user.phone_number.as_e164, message, sender)


class ConfigurationSession(models.Model):
    key = models.CharField(max_length=70, primary_key=True)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()
    phone_number = PhoneNumberField()
    is_phone_validated = models.BooleanField(default=False)
    gps_location = models.CharField(max_length=100, blank=True, null=True)  # GPS coordinates in format "lat lon"
    invited_user = models.BooleanField(default=False)

    def __str__(self):
        return self.key

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        if not self.expires:
            self.expires = now() + timedelta(hours=4)
        return super().save(*args, **kwargs)

    @staticmethod
    def generate_key():
        return token_hex()

    def is_valid(self):
        return self.expires > now()

    @property
    def country_code(self):
        coords = self.gps_location.split()
        lat = coords[0]
        lon = coords[1]
        geolocator = Nominatim(user_agent="PersonalID")
        location = geolocator.reverse(f"{lat} {lon}", language="en")
        address = location.raw.get("address", {})
        return address.get("country_code")


class SessionPhoneDevice(BasePhoneDevice):
    session = models.ForeignKey(ConfigurationSession, on_delete=models.CASCADE)
    # this is non-nullable field on the base SideChannelDevice, so make it nullable
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["phone_number", "session"], name="phone_number_session")]


class DeviceIntegritySample(models.Model):
    request_id = models.CharField(max_length=255, unique=True)
    device_id = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now_add=True)
    is_demo_user = models.BooleanField(default=False)
    google_verdict = models.JSONField()
    passed = models.BooleanField()
    passed_request_check = models.BooleanField()
    passed_app_integrity_check = models.BooleanField()
    passed_device_integrity_check = models.BooleanField()
    passed_account_details_check = models.BooleanField()

    class Meta:
        ordering = ["-created"]


class SessionUser(AnonymousUser):
    @property
    def is_authenticated(self):
        return True
