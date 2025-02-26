import base64
from collections import defaultdict

from django.db import transaction
from django.db.models import Prefetch
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from fcm_django.models import FCMDevice
from firebase_admin import messaging
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView

from messaging.models import Channel, Message, MessageDirection, MessageServer, MessageStatus
from messaging.serializers import (
    CCC_MESSAGE_ACTION,
    BulkMessageSerializer,
    MessageData,
    MessageSerializer,
    SingleMessageSerializer,
)
from messaging.task import make_request, send_messages_to_service_and_mark_status
from users.models import ConnectUser
from utils.rest_framework import ClientProtectedResourceAuth, MessagingServerAuth


def get_current_message_server(request):
    auth_header = request.headers.get("authorization")
    encoded_credentials = auth_header.split(" ")[1]
    decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
    client_id, client_secret = decoded_credentials.split(":")
    server = get_object_or_404(MessageServer, server_id=client_id)
    return server


class SendMessage(APIView):
    """
    Example:
    {
        "username": "user1",
        "title": "test title",
        "body": "test message",
        "data": {"test": "data"},
    }

    Response:
    {
        "all_success": true,
        "responses": [
            {"status": "success", "username": "user1"},
        ]
    }
    """

    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        serializer = SingleMessageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message = serializer.save()
        result = send_bulk_message(message)
        return JsonResponse(result, status=200)


class SendMessageBulk(APIView):
    """
    Send a bulk messages.

    Example:
    {
        "messages": [
            {
                "usernames": ["user1", "user2"],
                "title": "test title",
                "body": "test message",
                "data": {"test": "data"},
            },
        ]
    }

    Response:
    {
        "all_success": false,
        "messages": [
            {
                "all_success": false,
                "responses": [
                    {"status": "success", "username": "user1"},
                    {"status": "deactivated", "username": "user2"}
                ]
            },
        ]
    }
    """

    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        serializer = BulkMessageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        messages = serializer.save()

        global_all_success = True
        results = []
        for message in messages:
            message_result = send_bulk_message(message)
            results.append(message_result)
            if not message_result["all_success"]:
                global_all_success = False

        return JsonResponse({"messages": results, "all_success": global_all_success}, status=200)


def send_bulk_message(message):
    message_result = {"responses": []}
    message_all_success = True
    if not message.usernames:
        message_result["all_success"] = message_all_success
        return message_result

    active_devices = FCMDevice.objects.filter(user__username__in=message.usernames, active=True).values_list(
        "registration_id", "user__username"
    )
    registration_id_to_username = {reg_id: username for reg_id, username in active_devices}

    batch_response = FCMDevice.objects.send_message(
        _build_message(message),
        additional_registration_ids=list(registration_id_to_username),
        skip_registration_id_lookup=True,
    )

    for response, registration_id in zip(batch_response.response.responses, batch_response.registration_ids_sent):
        result = {"username": registration_id_to_username[registration_id]}
        message_result["responses"].append(result)
        if response.exception:
            message_all_success = False
            result["status"] = "error"
            if registration_id in batch_response.deactivated_registration_ids:
                result["status"] = "deactivated"
            else:
                result["error"] = response.exception.code
        else:
            result["status"] = "success"

    missing_usernames = set(message.usernames) - set(registration_id_to_username.values())
    for username in missing_usernames:
        message_all_success = False
        result = {"status": "deactivated", "username": username}
        message_result["responses"].append(result)

    message_result["all_success"] = message_all_success
    message_result["responses"].sort(key=lambda r: message.usernames.index(r["username"]))
    return message_result


def _build_message(message):
    notification = _build_notification(message)
    return messaging.Message(data=message.data, notification=notification)


def _build_notification(data):
    if data.title or data.body:
        return messaging.Notification(
            title=data.title,
            body=data.body,
        )


class CreateChannelView(APIView):
    authentication_classes = [MessagingServerAuth]

    def post(self, request, *args, **kwargs):
        data = request.data
        connect_id = data["connectid"]
        channel_source = data["channel_source"]
        server = get_current_message_server(request)
        user = get_object_or_404(ConnectUser, username=connect_id)
        channel, created = Channel.objects.get_or_create(
            server=server, connect_user=user, channel_source=channel_source
        )
        if created:
            message = MessageData(
                usernames=[channel.connect_user.username],
                title="Channel created",
                body="Please provide your consent to send/receive message.",
                data={
                    "key_url": str(server.key_url),
                    "action": CCC_MESSAGE_ACTION,
                    "channel_source": channel_source,
                    "channel_id": str(channel.channel_id),
                    "consent": str(channel.user_consent)
                },
            )
            # send fcm notification.
            send_bulk_message(message)
            return JsonResponse({"channel_id": str(channel.channel_id)}, status=status.HTTP_201_CREATED)
        else:
            return JsonResponse({"channel_id": str(channel.channel_id)}, status=status.HTTP_200_OK)


class SendServerConnectMessage(APIView):
    authentication_classes = [MessagingServerAuth]

    def post(self, request, *args, **kwargs):
        data = request.data
        content = data["content"]
        for field in ("nonce", "tag", "ciphertext"):
            if not content[field]:
                return JsonResponse({"errors": "invalid message content"}, status=status.HTTP_400_BAD_REQUEST)
        message_data = {
            "channel_id": data["channel"],
            "content": data["content"],
            "message_id": data["message_id"],
            "direction": MessageDirection.MOBILE,
        }
        message = Message(**message_data)
        message.save()
        channel = message.channel
        message_to_send = MessageData(usernames=[channel.connect_user.username], data=MessageSerializer(message).data)
        send_bulk_message(message_to_send)
        return JsonResponse(
            {"message_id": str(message.message_id)},
            status=status.HTTP_200_OK,
        )


class SendMobileConnectMessage(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        if not isinstance(data, list):
            data = [data]
        messages = []
        errors = set()
        for message in data:
            if not message.get("message_id"):
                errors.add("missing message_id")

            if not message.get("channel"):
                errors.add("missing channel_id")

            for field in ("nonce", "tag", "ciphertext"):
                if not message.get("content", {}).get(field):
                    errors.add("invalid message content")

            if errors:
                break

            message_data = {
                "message_id": message["message_id"],
                "content": message["content"],
                "channel_id": message["channel"],
                "direction": MessageDirection.SERVER,
            }
            messages.append(Message(**message_data))

        if errors:
            return JsonResponse({"errors": list(errors)}, status=status.HTTP_400_BAD_REQUEST)

        message_objs = Message.objects.bulk_create(messages)
        messages_ready_to_be_sent = defaultdict(lambda: {"messages": [], "url": None})
        messages_ready_to_be_sent_ids = []

        for msg in message_objs:
            channel = msg.channel
            server = channel.server

            channel_id = str(channel.channel_id)
            messages_ready_to_be_sent[channel_id]["messages"].append(MessageSerializer(msg).data)

            if messages_ready_to_be_sent[channel_id]["url"] is None:
                messages_ready_to_be_sent[channel_id]["url"] = server.delivery_url

            messages_ready_to_be_sent_ids.append(str(msg.message_id))

        send_messages_to_service_and_mark_status(messages_ready_to_be_sent, MessageStatus.SENT_TO_SERVICE)

        return JsonResponse(
            {"message_id": messages_ready_to_be_sent_ids},
            status=status.HTTP_201_CREATED,
        )


class RetrieveMessageView(APIView):
    def get(self, request, *args, **kwargs):
        user = request.user
        channels = (
            Channel.objects.filter(connect_user=user)
            .only("channel_id", "channel_source")
            .prefetch_related(
                Prefetch(
                    "message_set",
                    queryset=Message.objects.only("message_id", "channel", "timestamp", "content"),
                ),
                Prefetch("server", queryset=MessageServer.objects.only("key_url")),
            )
        )

        channels_data = []
        messages = []
        for channel in channels:
            channels_data.append(
                {
                    "channel_source": channel.channel_source,
                    "channel_id": str(channel.channel_id),
                    "key_url": channel.server.key_url,
                    "consent": channel.user_consent,
                }
            )
            channel_messages = Message.objects.filter(
                channel=channel, direction=MessageDirection.MOBILE, status=MessageStatus.PENDING
            )
            messages.extend(channel_messages)

        messages_data = MessageSerializer(messages, many=True).data

        return JsonResponse({"channels": channels_data, "messages": messages_data})


class UpdateConsentView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        channel_id = data.get("channel")
        consent = data.get("consent")

        if channel_id is None or consent is None:
            raise ValidationError("Both 'channel' and 'consent' fields are required.")

        channel = get_object_or_404(Channel, channel_id=channel_id)

        channel.user_consent = consent
        channel.save()

        json_data = {
            "channel_id": str(channel.channel_id),
            "consent": channel.user_consent,
        }

        response = make_request(url=channel.server.consent_url, json_data=json_data, secret=channel.server.secret_key)

        if response.status_code != status.HTTP_200_OK:
            return JsonResponse(
                {"error": "Failed to update consent service"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return JsonResponse({}, status=status.HTTP_200_OK)


class UpdateReceivedView(APIView):
    def post(self, request, *args, **kwargs):
        message_ids = request.data.get("messages", [])

        if not message_ids:
            return JsonResponse({}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            messages = Message.objects.select_for_update().filter(message_id__in=message_ids).select_related("channel")

            if not messages.exists():
                return JsonResponse({}, status=status.HTTP_404_NOT_FOUND)

            current_time = timezone.now()
            messages.update(received=current_time, status=MessageStatus.DELIVERED)

            # Group messages by their channel
            channel_messages = defaultdict(lambda: {"messages": [], "url": None})
            for message in messages:
                channel_id = str(message.channel.channel_id)

                channel_messages[channel_id]["messages"].append(
                    {
                        "message_id": str(message.message_id),
                        "received_on": str(current_time),
                    }
                )

                if channel_messages[channel_id]["url"] is None:
                    channel_messages[channel_id]["url"] = message.channel.server.callback_url

            # To-Do should be async.
            send_messages_to_service_and_mark_status(channel_messages, MessageStatus.CONFIRMED_RECEIVED)

        return JsonResponse({}, status=status.HTTP_200_OK)
