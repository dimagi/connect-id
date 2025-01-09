from django.http import JsonResponse
from fcm_django.models import DeviceType, FCMDevice


def create_update_device(user, token):
    device = FCMDevice.objects.filter(registration_id=token).first()

    if device:
        if device.user_id != user.id:
            return JsonResponse({"error": "FCM token already registered to another user"}, status=400)

        if device.active:
            return JsonResponse({}, status=202)

        active_device_exists = FCMDevice.objects.filter(user=user, active=True).exists()
        if active_device_exists:
            return JsonResponse({"warning": "Another device is already active"}, status=202)

        # reactivate this device
        device.active = True
        device.save()
        return JsonResponse({}, status=200)
    else:
        # deactivate all other devices
        FCMDevice.objects.filter(user=user).update(active=False)
        FCMDevice.objects.create(user=user, registration_id=token, type=DeviceType.ANDROID)
        return JsonResponse({}, status=201)
