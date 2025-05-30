import dataclasses

from rest_framework import serializers

from messaging.models import Message

CCC_MESSAGE_ACTION = "ccc_message"


@dataclasses.dataclass
class NotificationData:
    usernames: list[str] = None
    title: str = None
    body: str = None
    data: dict = None
    fcm_options: dict = dataclasses.field(default_factory=lambda: {})


class SingleMessageSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    usernames = serializers.ListField(child=serializers.CharField(), required=False)
    title = serializers.CharField(required=False)
    body = serializers.CharField(required=False)
    data = serializers.DictField(required=False)
    fcm_options = serializers.DictField(required=False, default={})

    def create(self, validated_data):
        username = validated_data.pop("username", None)
        if username:
            validated_data["usernames"] = [username]
        return NotificationData(**validated_data)


class BulkMessageSerializer(serializers.Serializer):
    messages = serializers.ListField(child=SingleMessageSerializer())

    def create(self, validated_data):
        return [NotificationData(**message) for message in validated_data["messages"]]


class MessageSerializer(serializers.ModelSerializer):
    ciphertext = serializers.SerializerMethodField()
    channel = serializers.SerializerMethodField()
    channel_name = serializers.SerializerMethodField()
    tag = serializers.SerializerMethodField()
    nonce = serializers.SerializerMethodField()
    message_id = serializers.SerializerMethodField()
    action = serializers.SerializerMethodField()

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
