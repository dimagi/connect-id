import uuid

from django.db import models
from django.utils import timezone

from users.models import ConnectUser


class Channel(models.Model):
    channel_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_consent = models.BooleanField(default=False)
    channel_source = models.TextField()
    connect_user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)
    key_url = models.URLField(max_length=200)
    callback_url = models.URLField(max_length=200)
    delivery_url = models.URLField(max_length=200)


class Message(models.Model):
    message_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    channel = models.ForeignKey(Channel, on_delete=models.CASCADE)
    content = models.BinaryField()
    timestamp = models.DateTimeField(default=timezone.now)
    received = models.DateTimeField(null=True, blank=True)
