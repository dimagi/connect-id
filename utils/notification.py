from django.db import transaction
from django.db.models import Prefetch
from fcm_django.models import MAX_MESSAGES_PER_BATCH, FCMDevice
from firebase_admin import messaging

from messaging.models import Notification, NotificationTypes
from messaging.serializers import NotificationData
from users.models import ConnectUser
from utils import batched


def send_bulk_notification(message: NotificationData) -> dict:
    return send_bulk_notifications([message])[0]


def send_bulk_notifications(messages: list[NotificationData]) -> list[dict]:
    """Send multiple notification messages, batching the FCM sends.

    Notifications are persisted per message (preserving ``Notification.save()`` semantics) inside a
    single transaction, then every FCM push is dispatched via ``messaging.send_each`` in batches of
    ``MAX_MESSAGES_PER_BATCH`` (the per-call API limit).

    Returns one result dict per input message, in input order::

        {"all_success": bool, "responses": [{"username", "status"[, "error"]}, ...]}
    """
    users_by_username = _load_active_users(messages)

    results_by_message = []
    pending = []

    with transaction.atomic():
        for message in messages:
            message_responses = []
            for username in dict.fromkeys(message.usernames or []):
                user = users_by_username.get(username)
                if user is None:
                    message_responses.append({"username": username, "status": "deactivated"})
                    continue

                notification = _get_or_create_notification(user, message)
                device = user.active_devices[0] if user.active_devices else None
                if device is None:
                    message_responses.append({"username": username, "status": "deactivated"})
                    continue

                fcm_message = notification.to_fcm_notification(fcm_options=message.fcm_options)
                fcm_message.token = device.registration_id
                result = {"username": username}
                pending.append((fcm_message, result))
                message_responses.append(result)
            results_by_message.append(message_responses)

    send_responses = _send_fcm_messages([fcm_message for fcm_message, _ in pending])
    _apply_send_results(pending, send_responses)

    return [_build_message_result(message_responses) for message_responses in results_by_message]


def _load_active_users(messages: list[NotificationData]):
    usernames = {username for message in messages for username in (message.usernames or [])}
    if not usernames:
        return {}
    users = ConnectUser.objects.filter(username__in=usernames, is_active=True).prefetch_related(
        Prefetch("fcmdevice_set", queryset=FCMDevice.objects.filter(active=True), to_attr="active_devices")
    )
    return {user.username: user for user in users}


def _get_or_create_notification(user: ConnectUser, message: NotificationData):
    data = message.data or {}
    is_messaging = data.get("notification_type") == NotificationTypes.MESSAGING.value
    message_id = data.get("message_id") if is_messaging else None
    payload = {"title": message.title, "body": message.body, "data": data}
    if message_id:
        notification, _ = Notification.objects.get_or_create(
            message_id=message_id, defaults={"user": user, "json": payload}
        )
    else:
        notification = Notification(user=user, json=payload)
        notification.save()
    return notification


def _send_fcm_messages(fcm_messages: list[messaging.Message]) -> list[messaging.SendResponse]:
    send_responses: list[messaging.SendResponse] = []
    for batch in batched(fcm_messages, MAX_MESSAGES_PER_BATCH):
        send_responses.extend(messaging.send_each(batch).responses)
    return send_responses


def _apply_send_results(pending, send_responses):
    for (_, result), send_response in zip(pending, send_responses):
        exception = send_response.exception
        if exception is None:
            result["status"] = "success"
        elif isinstance(exception, messaging.UnregisteredError):
            result["status"] = "deactivated"
        else:
            result["status"] = "error"
            result["error"] = exception.code

    registration_ids = [fcm_message.token for fcm_message, _ in pending]
    if registration_ids:
        FCMDevice.objects.deactivate_devices_with_error_results(registration_ids, send_responses)


def _build_message_result(message_responses: list[dict]):
    return {
        "all_success": all(response["status"] == "success" for response in message_responses),
        "responses": message_responses,
    }
