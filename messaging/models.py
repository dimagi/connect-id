import uuid

from django.db import models
from django.utils import timezone
from oauth2_provider.generators import generate_client_id, generate_client_secret

from users.models import ConnectUser


class MessageServer(models.Model):
    name = models.CharField(max_length=255)
    key_url = models.URLField(max_length=200)
    callback_url = models.URLField(max_length=200)
    delivery_url = models.URLField(max_length=200)
    consent_url = models.URLField(max_length=200)
    server_id = models.CharField(max_length=100, unique=True, default=generate_client_id, db_index=True)
    secret_key = models.CharField(
        max_length=255,
        default=generate_client_secret,
    )


class Channel(models.Model):
    channel_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_consent = models.BooleanField(default=False)
    channel_source = models.TextField()
    connect_user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)
    server = models.ForeignKey(MessageServer, on_delete=models.CASCADE)


class MessageStatus(models.TextChoices):
    PENDING = ("PENDING",)  # initially when message is received by connectid from mobile.
    SENT_TO_SERVICE = "SENT_TO_SERVICE"  # when message is sent to service
    DELIVERED = ("DELIVERED",)  # when mobile get the message and mark received on connectid
    CONFIRMED_RECEIVED = "CONFIRMED_RECEIVED"  # when message is mark received on service


class MessageDirection(models.TextChoices):
    MOBILE = "M"  # sent to mobile
    SERVER = "S"  # sent to server


class Message(models.Model):
    message_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    channel = models.ForeignKey(Channel, on_delete=models.CASCADE)
    content = models.JSONField()
    timestamp = models.DateTimeField(default=timezone.now)
    received = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=50, choices=MessageStatus.choices, default=MessageStatus.PENDING)
    # represents the direction the message is sent toward
    direction = models.CharField(max_length=4, choices=MessageDirection.choices)
