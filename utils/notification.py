from django.db.models import Prefetch
from fcm_django.models import FCMDevice
from firebase_admin import messaging
from firebase_admin.exceptions import FirebaseError

from messaging.models import Notification
from messaging.serializers import NotificationData
from users.models import ConnectUser


def send_bulk_notification(message: NotificationData):
    message_result = {"responses": []}
    message_all_success = True
    if not message.usernames:
        message_result["all_success"] = message_all_success
        return message_result

    users = ConnectUser.objects.filter(username__in=message.usernames, is_active=True).prefetch_related(
        Prefetch("fcmdevice_set", queryset=FCMDevice.objects.filter(active=True), to_attr="active_devices")
    )
    missing_users = set(message.usernames) - {u.username for u in users}

    for user in users:
        notification = Notification(
            user=user,
            json={"title": message.title, "body": message.body, "data": message.data},
        )
        notification.save()

        fcm_device = user.active_devices[0] if user.active_devices else None

        result = {"username": user.username}
        message_result["responses"].append(result)

        if fcm_device is not None:
            fcm_notification = notification.to_fcm_notification(fcm_options=message.fcm_options)
            try:
                fcm_device.send_message(fcm_notification)
            except messaging.UnregisteredError:
                message_all_success = False
                result["status"] = "deactivated"
            except FirebaseError as e:
                message_all_success = False
                result["status"] = "error"
                result["error"] = e.code
            else:
                result["status"] = "success"
        else:
            result["status"] = "deactivated"

    for username in missing_users:
        message_all_success = False
        result = {"status": "deactivated", "username": username}
        message_result["responses"].append(result)

    message_result["all_success"] = message_all_success
    message_result["responses"].sort(key=lambda r: message.usernames.index(r["username"]))
    return message_result
