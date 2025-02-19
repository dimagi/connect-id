from django.db import transaction
from django.db.models import Q
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from utils.notification import send_bulk_notification
from messaging.serializers import NotificationData
from oauth2_provider.decorators import protected_resource
from utils.rest_framework import ClientProtectedResourceAuth
from rest_framework import status as drf_status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView

from users.models import ConnectUser, PhoneDevice
from utils.twilio import lookup_telecom_provider
from .models import PaymentProfile


@api_view(['POST'])
def update_payment_profile_phone(request):
    user = request.user
    phone_number = request.data.get('phone_number')
    owner_name = request.data.get('owner_name')
    telecom_provider = lookup_telecom_provider(phone_number)
    payment_profile, created = PaymentProfile.objects.update_or_create(
        user=user,
        defaults={
            'phone_number': phone_number,
            'owner_name': owner_name,
            'telecom_provider': telecom_provider,
            'is_verified': False,
            'status': PaymentProfile.PENDING
        }
    )
    return PhoneDevice.send_otp_httpresponse(phone_number=payment_profile.phone_number, user=payment_profile.user)


@api_view(['POST'])
def confirm_payment_profile_otp(request):
    payment_profile = request.user.payment_profile
    device = PhoneDevice.objects.get(phone_number=payment_profile.phone_number, user=payment_profile.user)
    if not device.verify_token(request.data.get('token')):
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)

    payment_profile.is_verified = True
    payment_profile.save()
    return JsonResponse({"success": True})


class FetchPhoneNumbers(APIView):
    authentication_classes = [ClientProtectedResourceAuth]

    def get(self, request, *args, **kwargs):
        usernames = request.GET.getlist('usernames')
        status = request.GET.get("status")
        results = {}
        profiles = PaymentProfile.objects.filter(
            user__username__in=usernames)
        if status:
            profiles = profiles.filter(status=status)
        profiles = profiles.select_related("user")
        results["found_payment_numbers"] = [
            {
                "username": p.user.username,
                "phone_number": str(p.phone_number),
                "status": p.status,
            }
            for p in profiles
        ]
        return JsonResponse(results)


class ValidatePhoneNumbers(APIView):
    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        # List of dictionaries: [{"username": ..., "phone_number": ..., "status": ...}, ...]
        users_data = request.data["updates"]

        usernames = [data["username"] for data in users_data]
        status_map = {data["username"]: data["status"] for data in users_data}

        profiles = PaymentProfile.objects.filter(user__username__in=usernames).select_related("user")
        if len(profiles) != len(users_data):
            return Response(status=drf_status.HTTP_404_NOT_FOUND)

        profiles_to_update = []
        usernames_by_states = {
            "pending": [],
            "approved": [],
            "rejected": [],
        }

        for profile in profiles:
            username = profile.user.username
            requested_status = status_map.get(username)

            if profile.status != requested_status:
                profile.status = requested_status
                profiles_to_update.append(profile)

                usernames_by_states[requested_status].append(username)

        if profiles_to_update:
            PaymentProfile.objects.bulk_update(profiles_to_update, ["status"])

        if usernames_by_states["approved"]:
            send_bulk_notification(
                NotificationData(
                    usernames=usernames_by_states["approved"],
                    title="Your Payment Phone Number is approved",
                    body="Your payment phone number is approved and future payments will be made to this number.",
                    data={"action": "ccc_payment_info_confirmation", "confirmation_status": "approved"}
                )
            )
        if usernames_by_states["rejected"]:
            send_bulk_notification(
                NotificationData(
                    usernames=usernames_by_states["rejected"],
                    title="Your Payment Phone Number did not work",
                    body="Your payment number did not work. Please try to change to a different payment phone number",
                    data={"action": "ccc_payment_info_confirmation", "confirmation_status": "approved"}
                )
            )
        if usernames_by_states["pending"]:
            send_bulk_notification(
                NotificationData(
                    usernames=usernames_by_states["pending"],
                    title="Your Payment Phone Number is pending review",
                    body="Your payment phone number is pending review. Please wait for further updates.",
                    data={"action": "ccc_payment_info_confirmation", "confirmation_status": "pending"}
                )
            )
        result = {
            state: len(usernames_by_states[state])
            for state in ["approved", "rejected", "pending"]
        }
        return JsonResponse({"success": True, "result": result}, status=200)
