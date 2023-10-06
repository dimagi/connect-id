from http import HTTPStatus

from django.http import JsonResponse
from fcm_django.models import FCMDevice, _validate_exception_for_deactivation, FirebaseResponseDict
from firebase_admin import messaging, exceptions
from rest_framework.views import APIView

from utils.rest_framework import ClientProtectedResourceAuth


class SendMessage(APIView):
    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        device = FCMDevice.objects.filter(user__username=username, active=True).first()
        if not device:
            return JsonResponse({}, status=404)

        message = _build_message(request.data)
        fcm_response = device.send_message(message)
        if isinstance(fcm_response, messaging.SendResponse):
            return JsonResponse({}, status=200)
        elif isinstance(fcm_response, exceptions.FirebaseError):
            if _validate_exception_for_deactivation(fcm_response):
                return JsonResponse({"error": "Users device is not active"}, status=400)
            else:
                return JsonResponse({"error": "FCM Error", "fcm_error": fcm_response.code}, status=500)
        else:
            return JsonResponse({"error": "Unknown Error"}, status=500)


class SendMessageBulk(APIView):
    """
    Send a message to multiple users

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
    """
    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        messages = request.data.get('messages')
        if not messages:
            return JsonResponse({}, status=HTTPStatus.NO_CONTENT)

        results = []
        for message in messages:
            usernames = set(message.pop('usernames', []))
            if not usernames:
                results.append({"status": "success"})
                continue

            active_devices = FCMDevice.objects.filter(
                user__username__in=usernames, active=True
            ).values_list('registration_id', 'user__username')
            registration_id_to_username = {reg_id: username for reg_id, username in active_devices}
            batch_response = FCMDevice.objects.send_message(
                _build_message(message),
                additional_registration_ids=list(registration_id_to_username),
                skip_registration_id_lookup=True
            )
            for response, registration_id in zip(batch_response.response.responses, batch_response.registration_ids_sent):
                result = {"username": registration_id_to_username[registration_id]}
                results.append(result)
                if response.exception:
                    result["status"] = "error"
                    if registration_id in response.deactivated_registration_ids:
                        result["status"] = "deactivated"
                    else:
                        result["error"] = response.exception.code
                else:
                    result["status"] = "success"

            missing_usernames = set(usernames) - set(registration_id_to_username.values())
            for username in missing_usernames:
                result = {"status": "deactivated", "username": username}
                results.append(result)

        return JsonResponse({"results": results}, status=200)


def _build_message(data):
    notification = _build_notification(data)
    return messaging.Message(
        data=data.get('data'),
        notification=notification
    )


def _build_notification(data):
    if data.get('title') or data.get('body'):
        return messaging.Notification(
            title=data.get('title'),
            body=data.get('body'),
        )
