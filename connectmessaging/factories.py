from uuid import uuid4

import factory
from django.utils import timezone
from factory.django import DjangoModelFactory

from connectmessaging.models import Channel, Message
from users.factories import UserFactory


class ChannelFactory(DjangoModelFactory):
    class Meta:
        model = Channel

    channel_id = factory.LazyFunction(uuid4)
    user_consent = True
    connect_user = factory.SubFactory(UserFactory)


class MessageFactory(DjangoModelFactory):
    class Meta:
        model = Message

    message_id = factory.LazyFunction(uuid4)
    channel = factory.SubFactory(ChannelFactory)
    content = factory.Faker('binary', length=200)
    timestamp = factory.LazyFunction(timezone.now)
    received = None
