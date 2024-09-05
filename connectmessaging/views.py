from django.db.models import Prefetch
from django.utils import timezone
from rest_framework import status, views
from rest_framework.response import Response

from utils.rest_framework import ClientProtectedResourceAuth
from .models import Channel, Message
from .serializers import ChannelSerializer, MessageSerializer


class BaseAuthenticatedAPIView(views.APIView):
    authentication_classes = [ClientProtectedResourceAuth]


class CreateChannelView(BaseAuthenticatedAPIView):

    def post(self, request, *args, **kwargs):
        serializer = ChannelSerializer(data=request.data)
        if serializer.is_valid():
            channel = serializer.save()
            return Response({"channel_id": str(channel.channel_id)}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendMessageView(BaseAuthenticatedAPIView):
    def post(self, request, *args, **kwargs):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            get = serializer.validated_data.get('channel')
            channel = get
            if not Channel.objects.filter(channel_id=channel.channel_id, user_consent=True).exists():
                return Response({"error": "Consent is required for this channel"}, status=status.HTTP_403_FORBIDDEN)

            message = serializer.save()
            return Response({"message_id": str(message.message_id)}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RetrieveMessagesView(BaseAuthenticatedAPIView):
    def get(self, request, *args, **kwargs):
        user = request.user

        channels = Channel.objects.filter(connect_user=user).only('channel_id', 'channel_source',
                                                                  'key_url').prefetch_related(
            Prefetch('message_set', queryset=Message.objects.only('message_id', 'channel', 'timestamp'))
        )

        # Serialize channels
        channels_data = ChannelSerializer(channels, many=True).data

        messages = []
        for channel in channels:
            channel_messages = channel.message_set.all()
            messages.extend(channel_messages)

        messages_data = MessageSerializer(messages, many=True).data

        return Response({
            "channels": channels_data,
            "messages": messages_data
        })


class UpdateConsentView(BaseAuthenticatedAPIView):
    def post(self, request, *args, **kwargs):
        channel_id = request.data.get("channel")
        consent = request.data.get("consent")

        try:
            channel = Channel.objects.get(channel_id=channel_id)
            channel.user_consent = consent
            channel.save()
            return Response(status=status.HTTP_200_OK)
        except Channel.DoesNotExist:
            return Response({"error": "Channel not found"}, status=status.HTTP_404_NOT_FOUND)


class UpdateReceivedView(BaseAuthenticatedAPIView):
    def post(self, request, *args, **kwargs):
        message_ids = request.data.get("messages", [])

        messages = Message.objects.filter(message_id__in=message_ids)

        for message in messages:
            message.received = timezone.now()
            message.save()

        return Response(status=status.HTTP_200_OK)
