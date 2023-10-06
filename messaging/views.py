from django.http import JsonResponse
from fcm_django.models import FCMDevice, _validate_exception_for_deactivation
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

        notification = _build_notification(request.data)
        message = messaging.Message(
            data=request.data.get('data'),
            notification=notification
        )

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


def _build_notification(data):
    if data.get('title') or data.get('body'):
        return messaging.Notification(
            title=data.get('title'),
            body=data.get('body'),
        )
