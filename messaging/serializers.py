import dataclasses

from rest_framework import serializers

from messaging.models import Message


@dataclasses.dataclass
class MessageData:
    usernames: list[str] = None
    title: str = None
    body: str = None
    data: dict = None


class SingleMessageSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    usernames = serializers.ListField(child=serializers.CharField(), required=False)
    title = serializers.CharField(required=False)
    body = serializers.CharField(required=False)
    data = serializers.DictField(required=False)

    def create(self, validated_data):
        username = validated_data.pop("username", None)
        if username:
            validated_data["usernames"] = [username]
        return MessageData(**validated_data)


class BulkMessageSerializer(serializers.Serializer):
    messages = serializers.ListField(child=SingleMessageSerializer())

    def create(self, validated_data):
        return [MessageData(**message) for message in validated_data["messages"]]


class MessageSerializer(serializers.ModelSerializer):
    ciphertext = serializers.SerializerMethodField()
    tag = serializers.SerializerMethodField()
    nonce = serializers.SerializerMethodField()
    message_id = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "message_id",
            "channel",
            "ciphertext",
            "tag",
            "nonce",
            "timestamp",
            "received",
            "status",
        ]

    def get_ciphertext(self, obj):
        return obj.content["ciphertext"]

    def get_tag(self, obj):
        return obj.content["tag"]

    def get_nonce(self, obj):
        return obj.content["nonce"]

    def get_message_id(self, obj):
        return str(obj.message_id)
