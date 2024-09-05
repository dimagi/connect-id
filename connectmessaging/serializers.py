from rest_framework import serializers

from connectmessaging.models import Channel, Message


class ChannelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Channel
        fields = ['channel_id', 'user_consent', 'channel_source', 'connect_user',
                  'key_url', 'callback_url', 'delivery_url']


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ['message_id', 'channel', 'content', 'timestamp', 'received']

    def validate_content(self, value):
        if not value:
            raise serializers.ValidationError("Content cannot be empty.")
        return value