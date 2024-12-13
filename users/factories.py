import factory
from factory.django import DjangoModelFactory
from fcm_django.models import FCMDevice

from users.models import ConnectUser, Credential


class UserFactory(DjangoModelFactory):
    class Meta:
        model = ConnectUser

    username = factory.Faker('user_name')
    password = factory.PostGenerationMethodCall('set_password', 'testpass')
    phone_number = factory.Faker('phone_number')


class FCMDeviceFactory(DjangoModelFactory):
    class Meta:
        model = FCMDevice

    user = factory.SubFactory(UserFactory)
    registration_id = factory.Faker('uuid4')
    type = 'android'
    active = True


class CredentialFactory(DjangoModelFactory):
    class Meta:
        model = Credential

    name = factory.Faker('name')
    slug = factory.Faker('slug')
    organization_slug = factory.Faker('slug')
