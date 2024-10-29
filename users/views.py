from datetime import timedelta
from secrets import token_hex

from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import HttpResponse, JsonResponse
from django.utils.timezone import now
from django.views import View
from oauth2_provider.models import AccessToken, RefreshToken
from oauth2_provider.views.mixins import ClientProtectedResourceMixin
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView

from utils import get_ip
from utils.rest_framework import ClientProtectedResourceAuth
from .const import TEST_NUMBER_PREFIX
from .fcm_utils import create_update_device
from .models import (
    ConnectUser,
    Credential,
    PhoneDevice,
    RecoveryStatus,
    UserCredential,
    UserKey,
)


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
    user_data['recovery_phone_validation_deadline'] = now().date() + timedelta(days=7)

    # skip validation if number starts with special prefix
    if not user_data.get("phone_number", "").startswith(TEST_NUMBER_PREFIX):
        u = ConnectUser(**user_data)
        try:
            u.full_clean()
        except ValidationError as e:
            return JsonResponse(e.message_dict, status=400)

    user = ConnectUser.objects.create_user(**user_data)
    if data.get('fcm_token'):
        create_update_device(user, data['fcm_token'])
    db_key = UserKey.get_or_create_key_for_user(user)
    return JsonResponse({"secondary_phone_validate_by": user.recovery_phone_validation_deadline, "db_key": db_key.key})


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
    user.recovery_phone_validation_deadline = None
    user.save()
    return HttpResponse()


@api_view(['POST'])
@permission_classes([])
def recover_account(request):
    data = request.data
    user = ConnectUser.objects.get(phone_number=data["phone"], is_active=True)
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
    user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
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
    user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
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
    return JsonResponse({"secondary_phone": user.recovery_phone.as_e164})


@api_view(['POST'])
@permission_classes([])
def confirm_secondary_recovery_otp(request):
    data = request.data
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
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
    db_key = UserKey.get_or_create_key_for_user(user)
    return JsonResponse({"name": user.name, "username": user.username, "db_key": db_key.key})


@api_view(['POST'])
@permission_classes([])
def confirm_password(request):
    data = request.data
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY:
        return HttpResponse(status=401)
    password = data["password"]
    if not check_password(password, user.password):
        return HttpResponse(status=401)
    status.delete()
    db_key = UserKey.get_or_create_key_for_user(user)
    return JsonResponse({"name": user.name, "username": user.username, "secondary_phone_validate_by": user.recovery_phone_validation_deadline, "db_key": db_key.key})


@api_view(['POST'])
@permission_classes([])
def reset_password(request):
    data = request.data
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
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
        ConnectUser.objects.get(phone_number=phone_number, is_active=True)
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


@api_view(['POST'])
def set_recovery_pin(request):
    data = request.data
    user = request.user
    recovery_pin = data["recovery_pin"]
    user.set_recovery_pin(recovery_pin)
    user.save()
    return HttpResponse()


@api_view(['POST'])
@permission_classes([])
def confirm_recovery_pin(request):
    data = request.data
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if status.step != RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY:
        return HttpResponse(status=401)
    recovery_pin = data["recovery_pin"]
    if not user.check_recovery_pin(recovery_pin):
        return JsonResponse({"error": "Recovery PIN is incorrect"}, status=401)
    status.step = RecoveryStatus.RecoverySteps.RESET_PASSWORD
    status.save()
    db_key = UserKey.get_or_create_key_for_user(user)
    return JsonResponse({"name": user.name, "username": user.username, "secondary_phone_validate_by": user.recovery_phone_validation_deadline, "db_key": db_key.key})


@api_view(['GET'])
def fetch_db_key(request):
    db_key = UserKey.get_or_create_key_for_user(request.user)
    return JsonResponse({"db_key": db_key.key})


@api_view(['POST'])
def heartbeat(request):
    data = request.data
    user = request.user
    if not data.get('fcm_token'):
        return JsonResponse({}, status=200)

    fcm_token = data['fcm_token']
    return create_update_device(user, fcm_token)


class FetchUsers(ClientProtectedResourceMixin, View):
    required_scopes = ['user_fetch']

    def get(self, request, *args, **kwargs):
        numbers = request.GET.getlist('phone_numbers')
        results = {}
        found_users = list(
            ConnectUser.objects.filter(phone_number__in=numbers, is_active=True).values(
                "username", "phone_number", "name"
            )
        )
        results["found_users"] = found_users
        return JsonResponse(results)


class GetDemoUsers(ClientProtectedResourceMixin, View):
    required_scopes = ['user_fetch']

    def get(self, request, *args, **kwargs):
        demo_users = PhoneDevice.objects.filter(phone_number__startswith=TEST_NUMBER_PREFIX).values('phone_number', 'token')
        results = {"demo_users": list(demo_users)}
        return JsonResponse(results)


class FilterUsers(APIView):
    authentication_classes = [ClientProtectedResourceAuth]

    def get(self, request, *args, **kwargs):
        credential = request.query_params.get("credential")
        country = request.query_params.get("country")
        if not country and not credential:
            return JsonResponse({"error": "you must have a country or a credential"}, status=400)
        query = UserCredential.objects.filter(accepted=True)
        if credential is not None:
            query = query.filter(credential__slug=credential)
        if country is not None:
            query = query.filter(
                user__phone_number__startswith=country, user__is_active=True
            )
        users = query.select_related("user")
        user_list = [{"username": u.user.username, "phone_number": u.user.phone_number.as_e164, "name": u.user.name} for u in users]
        result = {"found_users": user_list}
        return JsonResponse(result)
        


class AddCredential(APIView):
    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        phone_numbers = request.data["users"]
        org_name = request.data["organization_name"]
        org_slug = request.data["organization"]
        credential_name = request.data["credential"]
        slug = f"{credential_name.lower().replace(' ', '_')}_{org_slug}"
        credential, _ = Credential.objects.get_or_create(name=credential_name, organization_slug=org_slug, defaults={"slug": slug})
        users = ConnectUser.objects.filter(
            phone_number__in=phone_numbers, is_active=True
        )
        for user in users:
            UserCredential.add_credential(user, credential, request)
        return HttpResponse()


@api_view(['GET'])
@permission_classes([])
def accept_credential(request, invite_id):
    try:
        credential = UserCredential.objects.get(invite_id=invite_id)
    except UserCredential.DoesNotExist:
        return HttpResponse("This link is invalid. Please try again", status=404)
    credential.accepted = True
    credential.save()
    return HttpResponse(
        "Thank you for accepting this credential. You will now have access to opportunities open "
        "to holders of this credential."
    )


class FetchCredentials(ClientProtectedResourceMixin, View):
    required_scopes = ['user_fetch']

    def get(self, request):
        org_slug = request.GET.get('org_slug', None)
        queryset = Credential.objects.all()
        if org_slug:
            queryset = queryset.filter(organization_slug=org_slug)

        credentials = queryset.values('name', 'slug')
        results = {"credentials": list(credentials)}
        return JsonResponse(results)


@api_view(["POST"])
@permission_classes([])
def initiate_deactivation(request):
    data = request.data
    phone_number = data["phone_number"]
    secret_key = data["secret_key"]
    try:
        user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
    except ConnectUser.DoesNotExist:
        return JsonResponse({"success": False})
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    user.initiate_deactivation()
    return JsonResponse({"success": True})


@api_view(["POST"])
@permission_classes([])
def confirm_deactivation(request):
    data = request.data
    phone_number = data["phone_number"]
    secret_key = data["secret_key"]
    deactivation_token = data["token"]
    try:
        user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
    except ConnectUser.DoesNotExist:
        return JsonResponse({"success": False})
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return HttpResponse(status=401)
    if user.deactivation_token == deactivation_token:
        user.is_active = False
        user.save()
        tokens = list(AccessToken.objects.filter(user=user)) + list(
            RefreshToken.objects.filter(user=user)
        )
        for token in tokens:
            token.revoke()
        return JsonResponse({"success": True})
    return JsonResponse({"success": False})
