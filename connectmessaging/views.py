import requests
from django.db.models import Prefetch
from django.utils import timezone
from rest_framework import status, views
from rest_framework.decorators import api_view
from rest_framework.response import Response

from messaging.serializers import Message as Msg
from messaging.views import send_bulk_message
from utils.rest_framework import ClientProtectedResourceAuth
from .models import Channel, Message
from .serializers import ChannelSerializer, MessageSerializer


class CommCareHQAPIException(Exception):
    pass


class BaseAuthenticatedAPIView(views.APIView):
    authentication_classes = [ClientProtectedResourceAuth]


def is_request_from_hq(request):
    host = request.META.get('HTTP_HOST')
    return host == "'commcarehq.org'"


class CreateChannelView(BaseAuthenticatedAPIView):

    def post(self, request, *args, **kwargs):
        serializer = ChannelSerializer(data=request.data)
        if serializer.is_valid():
            channel = serializer.save()
            message = Msg(
                usernames=[channel.connect_user.username],
                title="Channel created",
                body="A new channel has been created for you. Please provide your consent to proceed.",
                data={"keyUrl": channel.key_url}
            )
            send_bulk_message(message)
            return Response({"channel_id": str(channel.channel_id)}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendMessageView(BaseAuthenticatedAPIView):
    def post(self, request, *args, **kwargs):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            channel = serializer.validated_data.get('channel')
            if not Channel.objects.filter(channel_id=channel.channel_id, user_consent=True).exists():
                return Response({"error": "Consent is required for this channel"}, status=status.HTTP_403_FORBIDDEN)

            message = serializer.save()

            if is_request_from_hq(request):
                send_bulk_message(message)
            else:
                post_on_hq(channel.delivery_url, json_data=message)

            return Response({"message_id": str(message.message_id)}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def retrieve_message(request):
    user = request.user
    channels = Channel.objects.filter(connect_user=user).only('channel_id', 'channel_source',
                                                              'key_url').prefetch_related(
        Prefetch('message_set', queryset=Message.objects.only('message_id', 'channel', 'timestamp'))
    )

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

            #: TO-DO update the url
            url = "CONSENT_URL"
            json = {
                "channel_id": str(channel.channel_id),
                "consent": str(channel.user_consent)
            }
            post_on_hq(url, json)

            return Response(status=status.HTTP_200_OK)
        except Channel.DoesNotExist:
            return Response({"error": "Channel not found"}, status=status.HTTP_404_NOT_FOUND)


class UpdateReceivedView(BaseAuthenticatedAPIView):
    def post(self, request, *args, **kwargs):
        message_ids = request.data.get("messages", [])

        messages = Message.objects.filter(message_id__in=message_ids)

        for message in messages:
            message.received = timezone.now()

        Message.objects.bulk_update(messages, ["received"])

        if messages.exists():
            post_on_hq(messages.first().channel.delivery_url,
                       json_data=[message.message_id for message in messages])

        return Response(status=status.HTTP_200_OK)


def post_on_hq(url, json_data):
    #: TO-DO add authorization.
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, json=json_data, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        return CommCareHQAPIException({'status': 'error', 'message': str(e)}, )
