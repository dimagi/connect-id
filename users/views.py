import json

from django.core.exceptions import ValidationError
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from django_otp import match_token

from .models import ConnectUser, PhoneDevice

from utils import basicauth


# Create your views here.
@require_POST
@csrf_exempt
def register(request):
    data = json.loads(request.body)
    u = ConnectUser.objects.create_user(**data)
    try:
        u.full_clean()
    except ValidationError as e:
        return JsonResponse(e.message_dict, status=400)
    u.save()
    return HttpResponse()


def login(request):
    pass


def test(request):
    return HttpResponse('pong')


@require_POST
@csrf_exempt
@basicauth()
def validate_phone(request):
    # create otp device for user
    # send otp code via twilio
    print("hello")
    user = request.user
    otp_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.phone_number, user=user)
    otp_device.save()
    otp_device.generate_challenge()
    return HttpResponse()


@require_POST
@csrf_exempt
@basicauth()
def confirm_otp(request):
    # check otp code for user
    # mark phone as confirmed on user model
    user = request.user
    device = PhoneDevice.objects.get(phone_number=user.phone_number, user=user)
    data = json.loads(request.body)
    verified = device.verify_token(data.get('token'))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    user.phone_validated = True
    user.save()
    return HttpResponse()
