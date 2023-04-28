import json

from secrets import token_hex

from django.core.exceptions import ValidationError
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from django_otp import match_token

from .models import ConnectUser, PhoneDevice, RecoveryStatus

from utils import basicauth


# Create your views here.
@require_POST
@csrf_exempt
def register(request):
    data = json.loads(request.body)
    fields = ['username', 'password', 'phone_number', 'recovery_phone', 'name', 'dob']
    user_data = {}
    for field in fields:
        if data.get(field):
            user_data[field] = data[field]
    u = ConnectUser.objects.create_user(**user_data)
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


@require_POST
@csrf_exempt
@basicauth()
def validate_secondary_phone(request):
    # create otp device for user
    # send otp code via twilio
    user = request.user
    otp_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.recovery_phone, user=user)
    otp_device.save()
    otp_device.generate_challenge()
    return HttpResponse()


@require_POST
@csrf_exempt
@basicauth()
def confirm_secondary_otp(request):
    # check otp code for user
    # mark phone as confirmed on user model
    user = request.user
    device = PhoneDevice.objects.get(phone_number=user.recovery_phone, user=user)
    data = json.loads(request.body)
    verified = device.verify_token(data.get('token'))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    user.recovery_phone_validated = True
    user.save()
    return HttpResponse()


@require_POST
@csrf_exempt
def recover_account(request):
    data = json.loads(request.body)
    user = ConnectUser.objects.get(phone_number=data['phone'])
    device = PhoneDevice.objects.get(phone_number=user.phone_number, user=user)
    device.generate_challenge()
    secret = token_hex()
    status, _ = RecoveryStatus.objects.get_or_create(user=user)
    status.secret_key = secret
    status.step = RecoveryStatus.RecoverySteps.CONFIRM_PRIMARY
    status.save()
    return JsonResponse({'secret': secret})


@require_POST
@csrf_exempt
def confirm_recovery_otp(request):
    data = json.loads(request.body)
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.CONFIRM_PRIMARY:
        return HttpResponse(status=401)
    device = PhoneDevice.objects.get(phone_number=user.phone_number, user=user)
    verified = device.verify_token(data.get("token"))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    status.step = RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY
    status.save()
    return HttpResponse()


@require_POST
@csrf_exempt
def recover_secondary_phone(request):
    data = json.loads(request.body)
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY:
        return HttpResponse(status=401)
    device = PhoneDevice.objects.get(phone_number=user.recovery_phone, user=user)
    device.generate_challenge()
    status.step = RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY
    status.save()
    return HttpResponse()


@require_POST
@csrf_exempt
def confirm_secondary_recovery_otp(request):
    data = json.loads(request.body)
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY:
        return HttpResponse(status=401)
    device = PhoneDevice.objects.get(phone_number=user.recovery_phone, user=user)
    verified = device.verify_token(data.get('token'))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    status.step = RecoveryStatus.RecoverySteps.RESET_PASSWORD
    status.save()
    return HttpResponse()


@require_POST
@csrf_exempt
def reset_password(request):
    data = json.loads(request.body)
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.RESET_PASSWORD:
        return HttpResponse(status=401)
    user.set_password(data["password"])
    user.save()
    status.delete()
    return JsonResponse({"name": user.name, "username": user.username})
