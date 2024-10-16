from collections import defaultdict

from django.db.models import Prefetch
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status, views
from rest_framework.authentication import BasicAuthentication
from rest_framework.exceptions import ValidationError

from messaging.serializers import Message as Msg
from messaging.views import send_bulk_message
from utils.rest_framework import ClientProtectedResourceAuth
from .models import Channel, Message
from .serializers import ChannelSerializer, MessageSerializer
from .task import make_request_to_service


def is_request_from_hq(request):
    host = request.META.get("HTTP_HOST")
    return host == "commcarehq.org"


class CreateChannelView(views.APIView):
    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        serializer = ChannelSerializer(data=request.data)
        if serializer.is_valid():
            channel = serializer.save()
            message = Msg(
                usernames=[channel.connect_user.username],
                title="Channel created",
                body="Please provide your consent to send/receive message.",
                data={"keyUrl": channel.key_url},
            )
            send_bulk_message(message)
            return JsonResponse(
                {"channel_id": str(channel.channel_id)}, status=status.HTTP_201_CREATED
            )
        response = JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return response


class SendMessageView(views.APIView):
    # Will be called from mobile and other services.
    authentication_classes = [
        ClientProtectedResourceAuth,
        BasicAuthentication,
    ]

    def post(self, request, *args, **kwargs):
        data = None
        if isinstance(request.data, list):
            data = request.data
        else:
            data = [request.data]

        serializer = MessageSerializer(data=data, many=True)
        if serializer.is_valid():
            messages = serializer.save()
            for message in messages:
                channel = message.channel
                message_to_send = Msg(
                    usernames=[channel.connect_user.username],
                    data={"message_id": message.message_id, "content": message.content},
                )

                if is_request_from_hq(request):
                    send_bulk_message(message_to_send)
                else:
                    if not Channel.objects.filter(
                            channel_id=channel.channel_id, user_consent=True
                    ).exists():
                        return JsonResponse(
                            {
                                "error": "Consent is required for this channel.",
                                "channel": str(channel.channel_id),
                            },
                            status=status.HTTP_403_FORBIDDEN,
                        )
                    make_request_to_service(channel.delivery_url, json_data=message)

            return JsonResponse(
                {"message_id": [str(message.message_id) for message in messages]},
                status=status.HTTP_201_CREATED,
            )
        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RetrieveMessageView(views.APIView):
    def get(self, request, *args, **kwargs):
        user = request.user
        channels = (
            Channel.objects.filter(connect_user=user)
            .only("channel_id", "channel_source", "key_url")
            .prefetch_related(
                Prefetch(
                    "message_set",
                    queryset=Message.objects.only("message_id", "channel", "timestamp"),
                )
            )
        )

        channels_data = ChannelSerializer(channels, many=True).data

        messages = []
        for channel in channels:
            channel_messages = channel.message_set.all()
            messages.extend(channel_messages)

        messages_data = MessageSerializer(messages, many=True).data

        return JsonResponse({"channels": channels_data, "messages": messages_data})


class UpdateConsentView(views.APIView):
    def post(self, request, *args, **kwargs):
        channel_id = request.data.get("channel")
        consent = request.data.get("consent")

        if channel_id is None or consent is None:
            raise ValidationError("Both 'channel' and 'consent' fields are required.")

        channel = get_object_or_404(Channel, channel_id=channel_id)

        channel.user_consent = consent
        channel.save()

        #: TO-DO update the url
        url = "CONSENT_URL"
        json_data = {
            "channel_id": str(channel.channel_id),
            "consent": str(channel.user_consent),
        }
        response = make_request_to_service(url=url, json_data=json_data)

        if response.status_code != status.HTTP_200_OK:
            return JsonResponse(
                {"error": "Failed to update consent service"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return JsonResponse({}, status=status.HTTP_200_OK)


class UpdateReceivedView(views.APIView):
    def post(self, request, *args, **kwargs):
        message_ids = request.data.get("messages", [])

        messages = (
            Message.objects.select_for_update()
            .filter(message_id__in=message_ids)
            .select_related("channel")
        )

        if not messages.exists():
            return JsonResponse({}, status=status.HTTP_404_NOT_FOUND)

        current_time = timezone.now()
        messages.update(received=current_time)

        # Group messages by their channel
        channel_messages = defaultdict(lambda: {"messages": [], "delivery_url": None})
        for message in messages:
            channel_id = str(message.channel.channel_id)

            channel_messages[channel_id]["messages"].append(
                {
                    "message_id": str(message.message_id),
                    "received": str(current_time),
                }
            )

            if channel_messages[channel_id]["delivery_url"] is None:
                channel_messages[channel_id][
                    "delivery_url"
                ] = message.channel.delivery_url

        # Make request for each channel's delivery_url
        for channel_id, data in channel_messages.items():
            delivery_url = data["delivery_url"]
            messages = data["messages"]

            make_request_to_service(
                url=delivery_url,
                json_data={
                    "channel": channel_id,
                    "messages": messages,
                },
            )

        return JsonResponse({}, status=status.HTTP_200_OK)
