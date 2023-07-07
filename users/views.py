import json

from secrets import token_hex

from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from django_otp import match_token
from rest_framework.decorators import api_view, permission_classes

from .models import ConnectUser, PhoneDevice, RecoveryStatus

from utils import get_ip


# Create your views here.
@api_view(['POST'])
@permission_classes([])
def register(request):
    data = request.data
    fields = ['username', 'password', 'phone_number', 'recovery_phone', 'name', 'dob']
    user_data = {}
    for field in fields:
        if data.get(field):
            user_data[field] = data[field]
    user_data['ip_address'] = get_ip(request)
    # avoid create_user since it saves to the db without validation
    u = ConnectUser(**user_data)
    try:
        u.full_clean()
    except ValidationError as e:
        return JsonResponse(e.message_dict, status=400)
    u = ConnectUser.objects.create_user(**user_data)
    return HttpResponse()


def login(request):
    pass


def test(request):
    return HttpResponse('pong')

@api_view(['POST'])
def validate_phone(request):
    # create otp device for user
    # send otp code via twilio
    user = request.user
    otp_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.phone_number, user=user)
    otp_device.save()
    otp_device.generate_challenge()
    return HttpResponse()


@api_view(['POST'])
def confirm_otp(request):
    # check otp code for user
    # mark phone as confirmed on user model
    user = request.user
    device = PhoneDevice.objects.get(phone_number=user.phone_number, user=user)
    data = request.data
    verified = device.verify_token(data.get('token'))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    user.phone_validated = True
    user.save()
    return HttpResponse()


@api_view(['POST'])
def validate_secondary_phone(request):
    # create otp device for user
    # send otp code via twilio
    user = request.user
    otp_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.recovery_phone, user=user)
    otp_device.save()
    otp_device.generate_challenge()
    return HttpResponse()


@api_view(['POST'])
def confirm_secondary_otp(request):
    # check otp code for user
    # mark phone as confirmed on user model
    user = request.user
    device = PhoneDevice.objects.get(phone_number=user.recovery_phone, user=user)
    data = request.data
    verified = device.verify_token(data.get('token'))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    user.recovery_phone_validated = True
    user.save()
    return HttpResponse()


@api_view(['POST'])
@permission_classes([])
def recover_account(request):
    data = request.data
    user = ConnectUser.objects.get(phone_number=data['phone'])
    device = PhoneDevice.objects.get(phone_number=user.phone_number, user=user)
    device.generate_challenge()
    secret = token_hex()
    status, _ = RecoveryStatus.objects.get_or_create(user=user)
    status.secret_key = secret
    status.step = RecoveryStatus.RecoverySteps.CONFIRM_PRIMARY
    status.save()
    return JsonResponse({'secret': secret})


@api_view(['POST'])
@permission_classes([])
def confirm_recovery_otp(request):
    data = request.data
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


@api_view(['POST'])
@permission_classes([])
def recover_secondary_phone(request):
    data = request.data
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY:
        return HttpResponse(status=401)
    otp_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.recovery_phone, user=user)
    otp_device.save()
    otp_device.generate_challenge()
    status.step = RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY
    status.save()
    return HttpResponse()


@api_view(['POST'])
@permission_classes([])
def confirm_secondary_recovery_otp(request):
    data = request.data
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
    return JsonResponse({"name": user.name, "username": user.username})


@api_view(['POST'])
@permission_classes([])
def confirm_password(request):
    data = request.data
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY:
        return HttpResponse(status=401)
    password = data["password"]
    if not check_password(password, user.password):
        return HttpResponse(status=401)
    status.delete()
    return JsonResponse({"name": user.name, "username": user.username})


@api_view(['POST'])
@permission_classes([])
def reset_password(request):
    data = request.data
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.RESET_PASSWORD:
        return HttpResponse(status=401)
    password = data["password"]
    try:
        validate_password(password)
    except ValidationError as e:
        return JsonResponse(e.message_dict, status=400)
    user.set_password(password)
    user.save()
    status.delete()
    return HttpResponse()


@api_view(['GET'])
@permission_classes([])
def phone_available(request):
    phone_number = request.query_params.get('phone_number')
    if not phone_number:
        return HttpResponse(status=400)
    try:
        ConnectUser.objects.get(phone_number=phone_number)
    except ConnectUser.DoesNotExist:
        return HttpResponse()
    else:
        return HttpResponse(status=403)


@api_view(['POST'])
@permission_classes([])
def change_phone(request):
    data = request.data
    user = request.user
    error = None
    if user.phone_validated:
        error = 'You cannot change a validated number'
    elif user.phone_number != data['old_phone_number']:
        error = 'Old phone number does not match'
    if error:
        return JsonResponse({'error': error}, status=400)
    user.phone_number = data['new_phone_number']
    try:
        user.full_clean()
    except ValidationError as e:
        return JsonResponse(e.message_dict, status=400)
    user.save()
    return HttpResponse()


@api_view(['POST'])
def change_password(request):
    data = request.data
    user = request.user
    password = data["password"]
    try:
        validate_password(password)
    except ValidationError as e:
        return JsonResponse(e.message_dict, status=400)
    user.set_password(password)
    user.save()
    return HttpResponse()


@api_view(['POST'])
def update_profile(request):
    data = request.data
    user = request.user
    changed = False
    if data.get("name"):
        user.name = data["name"]
        changed = True
    if data.get("secondary_phone"):
        user.recovery_phone = data["secondary_phone"]
        changed = True
    if changed:
        try:
            user.full_clean()
        except ValidationError as e:
            return JsonResponse(e.message_dict, status=400)
        user.save()
    return HttpResponse()
