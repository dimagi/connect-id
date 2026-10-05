import uuid

from django.db import models
from django.utils import timezone
from firebase_admin import messaging
from oauth2_provider.generators import generate_client_id, generate_client_secret

from users.models import ConnectUser, ServerKeys
from utils.storage import get_message_attachment_storage


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
    server_credentials = models.ForeignKey(ServerKeys, on_delete=models.PROTECT, null=True)


class Channel(models.Model):
    channel_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_consent = models.BooleanField(default=True)
    channel_source = models.TextField()
    channel_name = models.TextField(null=True)
    connect_user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)
    server = models.ForeignKey(MessageServer, on_delete=models.CASCADE)

    @property
    def visible_name(self):
        return self.channel_name or self.channel_source


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

    # Rich message fields, all empty on plain messages. An empty version means version 1.
    version = models.PositiveSmallIntegerField(null=True, blank=True)
    # Encrypted like content: ciphertext, tag and nonce
    rich_text = models.JSONField(null=True, blank=True)
    format = models.CharField(max_length=50, null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            # Only rich messages expire, so the index stays small however many plain messages exist
            models.Index(
                fields=["expires_at"], name="message_expires_at", condition=models.Q(expires_at__isnull=False)
            ),
        ]


def attachment_storage_key(instance, filename):
    """Storage key built only from ids PersonalID minted; the uploaded filename is ignored."""
    return f"message-attachments/{instance.message.channel_id}/{instance.message_id}/{instance.id}"


class MessageAttachment(models.Model):
    """An encrypted file sent with a rich message. Its stored file is deleted with the row (see signals)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="attachments")
    # The sender's file name, which message text uses to refer to the attachment
    name = models.CharField(max_length=255)
    # MIME type, sent on the wire as "type"
    content_type = models.CharField(max_length=255)
    # Size of the encrypted file in bytes
    size = models.PositiveIntegerField()
    # Index in the sender's attachment list, so the device gets them in the order they were sent
    position = models.PositiveSmallIntegerField()
    file = models.FileField(upload_to=attachment_storage_key, storage=get_message_attachment_storage, max_length=255)

    class Meta:
        ordering = ["position"]
        constraints = [
            models.UniqueConstraint(fields=["message", "name"], name="unique_attachment_name_per_message"),
            models.UniqueConstraint(fields=["message", "position"], name="unique_attachment_position_per_message"),
        ]


class NotificationTypes(models.TextChoices):
    CONNECT = "CONNECT"  # notification from Connect
    MESSAGING = "MESSAGING"  # notification from Messaging sources


class Notification(models.Model):
    notification_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE)
    notification_type = models.CharField(
        max_length=50, choices=NotificationTypes.choices, default=NotificationTypes.CONNECT
    )
    # json contains notification title, body and data
    json = models.JSONField()
    timestamp = models.DateTimeField(default=timezone.now)
    received = models.DateTimeField(null=True, blank=True)

    # Only needed for Messaging notifications
    message = models.OneToOneField(Message, on_delete=models.CASCADE, null=True, blank=True)

    def save(self, **kwargs):
        if self.data is not None and self.data.get("notification_type", "") == NotificationTypes.MESSAGING.value:
            self.message_id = self.data.get("message_id")
            self.notification_type = NotificationTypes.MESSAGING.value
            # No need to save data for message notifications
            # it can be generated from the message using message_id
            del self.json["data"]

        super().save(**kwargs)

    def to_fcm_notification(self, fcm_options={}):
        data = {
            **self.data,
            "notification_id": str(self.notification_id),
            "notification_type": self.notification_type,
        }
        notification = None
        if self.title or self.body:
            notification = messaging.Notification(
                title=self.title,
                body=self.body,
            )
        return messaging.Message(
            data=data,
            notification=notification,
            fcm_options=messaging.FCMOptions(**fcm_options),
            android=messaging.AndroidConfig(priority="high"),
        )

    @property
    def is_received(self):
        return True if self.received else False

    @property
    def title(self):
        return self.json.get("title", "")

    @property
    def body(self):
        return self.json.get("body", "")

    @property
    def data(self):
        if self.notification_type == NotificationTypes.MESSAGING.value:
            from messaging.serializers import MessageSerializer

            return MessageSerializer(self.message).data
        # always return an empty dictionary, sometimes the data can be none
        return self.json.get("data") or {}
