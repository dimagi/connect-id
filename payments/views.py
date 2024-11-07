from django.http import JsonResponse, HttpResponse, Http404
from django.views.decorators.http import require_POST
from oauth2_provider.decorators import protected_resource
from utils.rest_framework import ClientProtectedResourceAuth
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from users.models import ConnectUser, PhoneDevice
from utils.twilio import lookup_telecom_provider
from .models import PaymentProfile


@api_view(['POST'])
def update_payment_profile_phone(request):
    user = request.user
    phone_number = request.data.get('phone_number')
    telecom_provider = lookup_telecom_provider(phone_number)
    payment_profile, created = PaymentProfile.objects.update_or_create(
        user=user,
        defaults={
            'phone_number': phone_number,
            'telecom_provider': telecom_provider,
            'is_verified': False,
            'is_validated': False
        }
    )
    return PhoneDevice.send_otp_httpresponse(phone_number=payment_profile.phone_number, user=payment_profile.user)


@api_view(['POST'])
def confirm_payment_profile_otp(request):
    PaymentProfile.objects.get(user=request.user)
    payment_profile = request.user.payment_profile
    device = PhoneDevice.objects.get(phone_number=payment_profile.phone_number, user=payment_profile.user)
    if not device.verify_token(request.data.get('token')):
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)

    payment_profile.is_verified = True
    payment_profile.save()
    return JsonResponse({"success": True})


@require_POST
@protected_resource(scopes=[])
def validate_payment_phone_number(request):
    username = request.data["username"]
    phone_number = request.data["phone_number"]
    user = ConnectUser.objects.get(username=username)
    profile = getattr(user, "payment_profile")

    if not profile or profile.phone_number != phone_number:
        raise Http404("Payment number not found")

    profile.is_validated = True
    return HttpResponse()


class ValidatePhoneNumber(APIView):
    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        username = request.data["username"]
        phone_number = request.data["phone_number"]
        user = ConnectUser.objects.get(username=username)
        profile = getattr(user, "payment_profile")

        if not profile or profile.phone_number != phone_number:
            raise Http404("Payment number not found")

        profile.is_validated = True
        profile.save()
        return HttpResponse()
