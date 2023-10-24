import dataclasses
from typing import List

from rest_framework import serializers


@dataclasses.dataclass
class Message:
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
        return Message(**validated_data)


class BulkMessageSerializer(serializers.Serializer):
    messages = serializers.ListField(child=SingleMessageSerializer())

    def create(self, validated_data):
        return [Message(**message) for message in validated_data["messages"]]

