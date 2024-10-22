import dataclasses
from typing import List

from rest_framework import serializers

from messaging.models import Message


@dataclasses.dataclass
class MessageData:
    usernames: List[str] = None
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
        username = validated_data.pop('username', None)
        if username:
            validated_data["usernames"] = [username]
        return MessageData(**validated_data)


class BulkMessageSerializer(serializers.Serializer):
    messages = serializers.ListField(child=SingleMessageSerializer())

    def create(self, validated_data):
        return [MessageData(**message) for message in validated_data["messages"]]


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ["message_id", "channel", "content", "timestamp", "received", "status"]
