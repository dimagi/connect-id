from fcm_django.models import FCMDevice
from firebase_admin import messaging

from messaging.serializers import NotificationData


def send_bulk_notification(message: NotificationData):
    message_result = {"responses": []}
    message_all_success = True
    if not message.usernames:
        message_result["all_success"] = message_all_success
        return message_result

    active_devices = FCMDevice.objects.filter(
        user__username__in=message.usernames, active=True
    ).values_list('registration_id', 'user__username')
    registration_id_to_username = {reg_id: username for reg_id, username in active_devices}

    batch_response = FCMDevice.objects.send_message(
        _build_message(message),
        additional_registration_ids=list(registration_id_to_username),
        skip_registration_id_lookup=True
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
