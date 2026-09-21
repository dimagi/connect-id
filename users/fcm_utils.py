from django.db.models import Q
from django.http import JsonResponse
from fcm_django.models import DeviceType, FCMDevice


def create_update_device(user, token):
    device = FCMDevice.objects.filter(registration_id=token).first()

    if device:
        if device.user_id != user.id:
            # Update ownership of device
            FCMDevice.objects.filter(Q(registration_id=token) | Q(user=user)).deactivate(
                reason="device_reassigned",
                source="create_update_device",
                metadata={"target_user_id": user.id},
            )
            device.active = True
            device.user = user
            device.save()
            return JsonResponse({}, status=200)

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
        FCMDevice.objects.filter(user=user).deactivate(
            reason="one_device_per_user",
            source="create_update_device",
            metadata={"user_id": user.id},
        )
        FCMDevice.objects.create(user=user, registration_id=token, type=DeviceType.ANDROID)
        return JsonResponse({}, status=201)
