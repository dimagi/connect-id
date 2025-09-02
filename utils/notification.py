from fcm_django.models import FCMDevice
from firebase_admin import messaging

from messaging.models import Notification
from messaging.serializers import NotificationData
from users.models import ConnectUser


def send_bulk_notification(message: NotificationData):
    message_result = {"responses": []}
    message_all_success = True
    if not message.usernames:
        message_result["all_success"] = message_all_success
        return message_result

    users = ConnectUser.objects.filter(username__in=message.usernames, is_active=True)
    missing_users = set()

    for user in users:
        notification = Notification(
            user=user,
            json={"title": message.title, "body": message.body, "data": message.data},
        )
        notification.save()

        fcm_device = FCMDevice.objects.filter(user=user, active=True).first()

        result = {"username": user.username}
        message_result["responses"].append(result)

        if fcm_device is not None:
            registration_id = fcm_device.registration_id
            fcm_notification = notification.to_fcm_notification(fcm_options=message.fcm_options)
            fcm_response = fcm_device.send_message(fcm_notification)

            if fcm_response.exception:
                message_all_success = False
                result["status"] = "error"
                if registration_id in fcm_response.deactivated_registration_ids:
                    result["status"] = "deactivated"
                else:
                    result["error"] = fcm_response.exception.code
            else:
                result["status"] = "success"

    for username in missing_users:
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
