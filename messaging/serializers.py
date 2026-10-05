import dataclasses

from rest_framework import serializers

from messaging.models import Message, Notification, NotificationTypes

CCC_MESSAGE_ACTION = "ccc_message"
MAX_BULK_MESSAGES = 5000
MAX_BULK_RECIPIENTS = 1000


@dataclasses.dataclass
class NotificationData:
    usernames: list[str] = None
    title: str = None
    body: str = None
    data: dict = None
    fcm_options: dict = dataclasses.field(default_factory=lambda: {})


def _recipients(message: dict) -> list[str]:
    """Recipient usernames of a validated single-message payload, from either the singular or plural key."""
    usernames = list(message.get("usernames") or [])
    username = message.get("username")
    if username:
        usernames.append(username)
    return usernames


class SingleMessageSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    usernames = serializers.ListField(child=serializers.CharField(), required=False)
    title = serializers.CharField(required=False)
    body = serializers.CharField(required=False)
    data = serializers.DictField(required=False)
    fcm_options = serializers.DictField(required=False, default={})

    def create(self, validated_data):
        validated_data = dict(validated_data)
        username = validated_data.pop("username", None)
        if username:
            usernames = list(validated_data.get("usernames") or [])
            if username not in usernames:
                usernames.append(username)
            validated_data["usernames"] = usernames
        return NotificationData(**validated_data)


class BulkMessageSerializer(serializers.Serializer):
    messages = serializers.ListField(child=SingleMessageSerializer(), max_length=MAX_BULK_MESSAGES)

    def validate_messages(self, messages):
        recipients = sum(len(set(_recipients(message))) for message in messages)
        if recipients > MAX_BULK_RECIPIENTS:
            raise serializers.ValidationError(
                f"Too many recipients: {recipients} (maximum {MAX_BULK_RECIPIENTS} per request). "
                f"Split the messages across multiple requests."
            )
        return messages

    def create(self, validated_data):
        child = self.fields["messages"].child
        return [child.create(message) for message in validated_data["messages"]]


class MessageSerializer(serializers.ModelSerializer):
    """A message as the push, retrieve_messages and reply forwarding carry it.

    Its output must not change: apps in the field parse it, and push data has a 4 KB limit. Rich
    fields go only in SyncedMessageSerializer. Pinned by test_message_projections.
    """

    ciphertext = serializers.SerializerMethodField()
    channel = serializers.SerializerMethodField()
    channel_name = serializers.SerializerMethodField()
    tag = serializers.SerializerMethodField()
    nonce = serializers.SerializerMethodField()
    message_id = serializers.SerializerMethodField()
    action = serializers.SerializerMethodField()
    notification_type = serializers.CharField(default=NotificationTypes.MESSAGING.value)
    title = serializers.SerializerMethodField()
    body = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "message_id",
            "channel",
            "channel_name",
            "ciphertext",
            "tag",
            "nonce",
            "timestamp",
            "status",
            "action",
            "notification_type",
            "title",
            "body",
        ]

    def get_ciphertext(self, obj):
        return obj.content["ciphertext"]

    def get_tag(self, obj):
        return obj.content["tag"]

    def get_nonce(self, obj):
        return obj.content["nonce"]

    def get_message_id(self, obj):
        return str(obj.message_id)

    def get_action(self, obj):
        return CCC_MESSAGE_ACTION

    def get_channel(self, obj):
        return str(obj.channel_id)

    def get_channel_name(self, obj):
        return obj.channel.visible_name

    def get_title(self, obj):
        return "New Connect Message"

    def get_body(self, obj):
        return f"You received a new message from {obj.channel.visible_name}"


class SyncedMessageSerializer(MessageSerializer):
    """A message as the device syncs it from retrieve_notifications.

    Plain messages are exactly MessageSerializer's output. Rich messages add their cleartext
    fields and attachment list; fields the sender did not set are left out.
    """

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.version is None:
            return representation
        rich_fields = {
            "version": instance.version,
            "rich_text": instance.rich_text,
            "format": instance.format,
            "attachments": [
                {
                    "id": str(attachment.id),
                    "name": attachment.name,
                    "type": attachment.content_type,
                    "size": attachment.size,
                }
                for attachment in instance.attachments.all()
            ],
            "expires_at": serializers.DateTimeField().to_representation(instance.expires_at)
            if instance.expires_at
            else None,
        }
        representation.update({key: value for key, value in rich_fields.items() if value is not None})
        return representation


class EncryptedTextSerializer(serializers.Serializer):
    ciphertext = serializers.CharField()
    tag = serializers.CharField()
    nonce = serializers.CharField()


class RichAttachmentSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    type = serializers.CharField(max_length=255)
    size = serializers.IntegerField(min_value=1)


class SendRichMessageSerializer(serializers.Serializer):
    """Shape of the JSON part of a rich send. The rules between fields are in messaging.rich_messages."""

    version = serializers.IntegerField()
    channel = serializers.UUIDField()
    message_id = serializers.UUIDField()
    content = EncryptedTextSerializer()
    rich_text = EncryptedTextSerializer(required=False)
    format = serializers.CharField(max_length=50, required=False)
    attachments = serializers.ListField(child=RichAttachmentSerializer(), required=False, default=list)
    expires_at = serializers.DateTimeField(required=False)


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = (
            "notification_id",
            "notification_type",
            "timestamp",
        )

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        if instance.notification_type == NotificationTypes.MESSAGING.value and instance.message is not None:
            # The sync carries rich fields; the push (Notification.data) does not
            data = SyncedMessageSerializer(instance.message).data
        else:
            data = getattr(instance, "data", {})
        # Add all keys from data dictionary to the top-level
        if isinstance(data, dict):
            rep.update(data)
        return rep
