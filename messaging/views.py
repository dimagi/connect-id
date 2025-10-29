import base64
from collections import defaultdict
from uuid import UUID

import sentry_sdk
from django.db import IntegrityError, transaction
from django.db.models import Prefetch
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.timezone import now
from fcm_django.models import FCMDevice
from firebase_admin import messaging
from psycopg2.errors import ForeignKeyViolation
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.views import APIView

from messaging.const import ErrorCodes
from messaging.models import Channel, Message, MessageDirection, MessageServer, MessageStatus, Notification
from messaging.serializers import (
    CCC_MESSAGE_ACTION,
    BulkMessageSerializer,
    MessageSerializer,
    NotificationData,
    NotificationSerializer,
    SingleMessageSerializer,
)
from messaging.task import CommCareHQAPIException, make_request, send_messages_to_service_and_mark_status
from users.models import ConnectUser
from utils.notification import send_bulk_notification
from utils.rest_framework import ClientProtectedResourceAuth, MessagingServerAuth


def get_current_message_server(request):
    auth_header = request.headers.get("authorization")
    encoded_credentials = auth_header.split(" ")[1]
    decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
    client_id, client_secret = decoded_credentials.split(":")
    server = get_object_or_404(MessageServer, server_credentials__client_id=client_id)
    return server


class SendMessage(APIView):
    """
    Example:
    {
        "username": "user1",
        "title": "test title",
        "body": "test message",
        "data": {"test": "data"},
        "fcm_options": {"analytics_label": "label"}
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
        result = send_bulk_notification(message)
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
                "fcm_options": {"analytics_label": "label"}
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
            message_result = send_bulk_notification(message)
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
    return messaging.Message(
        data=message.data,
        notification=notification,
        fcm_options=messaging.FCMOptions(**message.fcm_options),
        android=messaging.AndroidConfig(priority="high"),
    )


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
        channel_name = data.get("channel_name")
        server = get_current_message_server(request)
        user = get_object_or_404(ConnectUser, username__iexact=connect_id)
        channel, created = Channel.objects.get_or_create(
            server=server, connect_user=user, channel_source=channel_source, defaults={"channel_name": channel_name}
        )
        response_dict = {"channel_id": str(channel.channel_id), "consent": channel.user_consent}
        if created:
            message = NotificationData(
                usernames=[channel.connect_user.username],
                title="New Channel",
                body=f"A new messaging channel is available from {channel.visible_name}, press here to view",
                data={
                    "key_url": str(server.key_url),
                    "action": CCC_MESSAGE_ACTION,
                    "channel_source": channel_source,
                    "channel_id": str(channel.channel_id),
                    "consent": str(channel.user_consent),
                    "channel_name": channel.visible_name,
                },
            )
            # send fcm notification.
            send_bulk_notification(message)
            return JsonResponse(response_dict, status=status.HTTP_201_CREATED)
        else:
            return JsonResponse(response_dict, status=status.HTTP_200_OK)


class SendServerConnectMessage(APIView):
    authentication_classes = [MessagingServerAuth]

    def post(self, request, *args, **kwargs):
        data = request.data
        content = data["content"]
        for field in ("nonce", "tag", "ciphertext"):
            if not content[field]:
                return JsonResponse({"errors": ErrorCodes.INVALID_MESSAGE_CONTENT}, status=status.HTTP_400_BAD_REQUEST)
        message_data = {
            "channel_id": data["channel"],
            "content": data["content"],
            "message_id": data["message_id"],
            "direction": MessageDirection.MOBILE,
        }
        message = Message(**message_data)
        try:
            message.save()
        except (IntegrityError, ForeignKeyViolation):
            return JsonResponse({"errors": ErrorCodes.CHANNEL_DOES_NOT_EXIST}, status=status.HTTP_400_BAD_REQUEST)
        channel = message.channel
        fcm_options = data.get("fcm_options", {})
        message_to_send = NotificationData(
            usernames=[channel.connect_user.username],
            data=MessageSerializer(message).data,
            title="New Connect Message",
            body=f"You received a new message from {channel.visible_name}",
            fcm_options=fcm_options,
        )
        send_bulk_notification(message_to_send)
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
        message_ids = []
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
            message_ids.append(message["message_id"])

        if errors:
            return JsonResponse({"errors": list(errors)}, status=status.HTTP_400_BAD_REQUEST)

        existing_messages = Message.objects.filter(message_id__in=message_ids)
        if existing_messages:
            existing_message_ids = list(existing_messages.values_list("message_id", flat=True))
            new_messages = [msg for msg in messages if UUID(msg.message_id) not in existing_message_ids]
        else:
            existing_message_ids = []
            new_messages = messages
        message_objs = Message.objects.bulk_create(new_messages)
        message_objs += list(existing_messages)
        messages_ready_to_be_sent = defaultdict(lambda: {"messages": [], "url": None})
        messages_ready_to_be_sent_ids = []

        for msg in message_objs:
            if msg.status != MessageStatus.PENDING:
                continue

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
                    "channel_source": channel.visible_name,
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

        status_code = status.HTTP_200_OK
        response = {}

        try:
            make_request(
                url=channel.server.consent_url,
                json_data=json_data,
                secret=channel.server.server_credentials.secret_key,
            )

        except CommCareHQAPIException:
            response = {"error": "Failed to update consent for channel."}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        return JsonResponse(response, status=status_code)


class UpdateReceivedView(APIView):
    def post(self, request, *args, **kwargs):
        message_ids = request.data.get("messages", [])

        if not message_ids:
            return JsonResponse({}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            messages = Message.objects.select_for_update().filter(message_id__in=message_ids).select_related("channel")

            if not messages.exists():
                return JsonResponse({}, status=status.HTTP_404_NOT_FOUND)

            current_time = now()
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


class RetrieveNotificationView(ListAPIView):
    serializer_class = NotificationSerializer

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user, received__isnull=True)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        notifications_data = serializer.data

        # Get all channels for the user
        user_channels = Channel.objects.filter(connect_user=request.user)
        channels_data = []

        for channel in user_channels:
            channels_data.append(
                {
                    "channel_id": str(channel.channel_id),
                    "channel_source": channel.visible_name,
                    "key_url": channel.server.key_url,
                    "consent": channel.user_consent,
                }
            )
        response_data = {
            "notifications": notifications_data,
            "channels": channels_data,
        }
        return JsonResponse(response_data, status=status.HTTP_200_OK, safe=False)


class UpdateNotificationReceivedView(APIView):
    def post(self, request, *args, **kwargs):
        notification_ids = request.data.get("notifications", [])

        if not notification_ids:
            return JsonResponse({}, status=status.HTTP_400_BAD_REQUEST)

        valid_notification_ids = []
        for notification_id in notification_ids:
            try:
                uuid = UUID(str(notification_id))
                valid_notification_ids.append(uuid)
            except ValueError as e:
                sentry_sdk.capture_exception(e)

        with transaction.atomic():
            updated_count = Notification.objects.filter(notification_id__in=valid_notification_ids).update(
                received=now()
            )
            if updated_count <= 0:
                return JsonResponse({}, status=status.HTTP_404_NOT_FOUND)

        return JsonResponse({}, status=status.HTTP_200_OK)
