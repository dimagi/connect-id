from datetime import timedelta

import factory
from django.utils.timezone import now
from factory.django import DjangoModelFactory
from fcm_django.models import FCMDevice

from users.models import (
    ConfigurationSession,
    ConnectUser,
    Credential,
    IssuingAuthority,
    PhoneDevice,
    RecoveryStatus,
    ServerKeys,
    SessionPhoneDevice,
    UserCredential,
)


class UserFactory(DjangoModelFactory):
    class Meta:
        model = ConnectUser

    username = factory.Faker("user_name")
    password = factory.PostGenerationMethodCall("set_password", "testpass")
    phone_number = factory.Faker("phone_number")
    deactivation_token = factory.Faker("bothify", text="????####")
    deactivation_token_valid_until = now() + timedelta(days=1)


class FCMDeviceFactory(DjangoModelFactory):
    class Meta:
        model = FCMDevice

    user = factory.SubFactory(UserFactory)
    registration_id = factory.Faker("uuid4")
    type = "android"
    active = True


class CredentialFactory(DjangoModelFactory):
    class Meta:
        model = Credential

    title = factory.Faker("name")
    type = Credential.CredentialTypes.DELIVER
    slug = factory.Faker("uuid4")


class UserCredentialFactory(DjangoModelFactory):
    class Meta:
        model = UserCredential

    user = factory.SubFactory(UserFactory)
    credential = factory.SubFactory(CredentialFactory)


class PhoneDeviceFactory(DjangoModelFactory):
    class Meta:
        model = PhoneDevice

    phone_number = factory.Faker("phone_number")
    token = factory.Faker("bothify", text="????####")
    user = factory.SubFactory(UserFactory)


class RecoveryStatusFactory(DjangoModelFactory):
    class Meta:
        model = RecoveryStatus

    secret_key = factory.Faker("uuid4")
    user = factory.SubFactory(UserFactory)
    step = RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY


class ConfigurationSessionFactory(DjangoModelFactory):
    class Meta:
        model = ConfigurationSession

    key = factory.Faker("uuid4")
    phone_number = "+27738156127"
    device_id = factory.Faker("uuid4")


class SessionPhoneDeviceFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = SessionPhoneDevice

    phone_number = factory.Faker("phone_number")
    session = factory.SubFactory(ConfigurationSessionFactory)
    token = factory.Faker("bothify", text="????##")


class IssuingAuthorityFactory(DjangoModelFactory):
    class Meta:
        model = IssuingAuthority

    issuing_authority = IssuingAuthority.IssuingAuthorityTypes.HQ
    issuer_environment = IssuingAuthority.IssuingAuthorityEnvironments.PRODUCTION


class ServerKeysFactory(DjangoModelFactory):
    class Meta:
        model = ServerKeys

    name = factory.Faker("name")
