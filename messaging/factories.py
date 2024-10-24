from uuid import uuid4

import factory
from django.utils import timezone
from factory.django import DjangoModelFactory
from oauth2_provider.models import Application

from messaging.models import Channel, Message, MessageServer
from users.factories import UserFactory


class ApplicationFactory(DjangoModelFactory):
    class Meta:
        model = Application

    client_id = factory.Faker("uuid4")
    client_secret = factory.Faker("uuid4")
    client_type = "confidential"
    authorization_grant_type = factory.Faker("random_element", elements=["authorization-code", "implicit", "password",
                                                                         "client-credentials"])
    name = factory.Faker("company")


class ServerFactory(DjangoModelFactory):
    class Meta:
        model = MessageServer

    delivery_url = factory.Faker("url")
    consent_url = factory.Faker("url")
    callback_url = factory.Faker("url")
    key_url = factory.Faker("url")
    oauth_application = factory.SubFactory(ApplicationFactory)


class ChannelFactory(DjangoModelFactory):
    class Meta:
        model = Channel

    channel_id = factory.LazyFunction(uuid4)
    user_consent = True
    connect_user = factory.SubFactory(UserFactory)
    server = factory.SubFactory(ServerFactory)


class MessageFactory(DjangoModelFactory):
    class Meta:
        model = Message

    message_id = factory.LazyFunction(uuid4)
    channel = factory.SubFactory(ChannelFactory)
    content = factory.Faker("binary", length=200)
    timestamp = factory.LazyFunction(timezone.now)
    received = None
