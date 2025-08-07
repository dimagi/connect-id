import base64
import logging
from datetime import timedelta
from secrets import token_hex
from urllib.parse import urlencode, urlparse

import requests
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db.models import Count, F
from django.db.models.functions import TruncMonth
from django.db.utils import IntegrityError
from django.http import HttpResponse, JsonResponse
from django.utils.timezone import now
from django.views import View
from firebase_admin import auth
from googleapiclient.errors import HttpError
from oauth2_provider.models import AccessToken, RefreshToken
from oauth2_provider.views.mixins import ClientProtectedResourceMixin
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.views import APIView

from services.ai.ocs import OpenChatStudio
from utils import get_ip, get_sms_sender, send_sms
from utils.app_integrity.decorators import require_app_integrity
from utils.app_integrity.exceptions import DuplicateSampleRequestError
from utils.app_integrity.google_play_integrity import AppIntegrityService
from utils.rest_framework import ClientProtectedResourceAuth

from .auth import IssuingCredentialsAuth, SessionTokenAuthentication
from .const import NO_RECOVERY_PHONE_ERROR, TEST_NUMBER_PREFIX, ErrorCodes, SMSMethods
from .exceptions import RecoveryPinNotSetError
from .fcm_utils import create_update_device
from .models import (
    ConfigurationSession,
    ConnectUser,
    Credential,
    IssuingAuthority,
    PhoneDevice,
    RecoveryStatus,
    SessionPhoneDevice,
    UserCredential,
    UserKey,
)
from .serializers import CredentialSerializer
from .services import upload_photo_to_s3

logger = logging.getLogger(__name__)


@api_view(["POST"])
@permission_classes([])
def register(request):
    data = request.data
    fields = ["username", "password", "phone_number", "recovery_phone", "name", "dob"]
    user_data = {}
    for field in fields:
        if data.get(field):
            user_data[field] = data[field]
    user_data["ip_address"] = get_ip(request)
    user_data["recovery_phone_validation_deadline"] = now().date() + timedelta(days=7)

    # skip validation if number starts with special prefix
    if not user_data.get("phone_number", "").startswith(TEST_NUMBER_PREFIX):
        u = ConnectUser(**user_data)
        try:
            u.full_clean()
        except ValidationError as e:
            return JsonResponse(e.message_dict, status=400)

    user = ConnectUser.objects.create_user(**user_data)
    if data.get("fcm_token"):
        create_update_device(user, data["fcm_token"])
    db_key = UserKey.get_or_create_key_for_user(user)
    return JsonResponse({"secondary_phone_validate_by": user.recovery_phone_validation_deadline, "db_key": db_key.key})


@api_view(["POST"])
@permission_classes([])
@require_app_integrity
def start_device_configuration(request):
    data = request.data
    logger.info(f"Start configuration for phone: {data}")
    if not data.get("phone_number"):
        return JsonResponse(
            {"error_code": ErrorCodes.MISSING_DATA, "error_sub_code": "PHONE_NUMBER_REQUIRED"},
            status=400,
        )

    is_demo_user = data["phone_number"].startswith(TEST_NUMBER_PREFIX)
    token_session = ConfigurationSession(
        phone_number=data["phone_number"],
        is_phone_validated=is_demo_user,  # demo users are always considered validated
        gps_location=data.get("gps_location"),
        invited_user=request.invited_user,
    )

    try:
        if token_session.country_code in settings.BLACKLISTED_COUNTRY_CODES:
            return JsonResponse({"error_code": ErrorCodes.UNSUPPORTED_COUNTRY}, status=403)
    except (ValueError, AttributeError, IndexError):
        # TODO: This should fail with a JSON response instead once mobile starts sending GPS data to this endpoint
        logger.error(f"Invalid location data for phone number ...{data['phone_number'][-6:]}")

    token_session.save()
    response_data = {
        "required_lock": ConnectUser.get_device_security_requirement(data["phone_number"], request.invited_user),
        "demo_user": is_demo_user,
        "token": token_session.key,
        "sms_method": SMSMethods.PERSONAL_ID if request.invited_user else SMSMethods.FIREBASE,
    }
    return JsonResponse(response_data)


def login(request):
    pass


def test(request):
    return HttpResponse("pong")


@api_view(["POST"])
def validate_phone(request):
    user = request.user
    otp_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.phone_number, user=user)
    otp_device.generate_challenge()
    return HttpResponse()


@api_view(["POST"])
@authentication_classes([SessionTokenAuthentication])
def validate_firebase_id_token(request):
    id_token = request.data.get("token")
    if not id_token:
        return JsonResponse({"error": ErrorCodes.MISSING_TOKEN}, status=400)
    try:
        decoded_token = auth.verify_id_token(id_token)
    except Exception:
        return JsonResponse({"error": ErrorCodes.FAILED_VALIDATING_TOKEN}, status=400)

    if not decoded_token.get("uid"):
        return JsonResponse({"error": ErrorCodes.INVALID_TOKEN}, status=400)
    if decoded_token.get("phone_number") != request.auth.phone_number.as_e164:
        return JsonResponse({"error": ErrorCodes.PHONE_MISMATCH}, status=400)
    request.auth.is_phone_validated = True
    request.auth.save()
    return HttpResponse()


@api_view(["POST"])
def confirm_otp(request):
    # check otp code for user
    # mark phone as confirmed on user model
    user = request.user
    device = PhoneDevice.objects.get(phone_number=user.phone_number, user=user)
    data = request.data
    verified = device.verify_token(data.get("token"))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    user.phone_validated = True
    user.save()
    return HttpResponse()


@api_view(["POST"])
def validate_secondary_phone(request):
    user = request.user
    if not user.recovery_phone:
        return JsonResponse({"error": NO_RECOVERY_PHONE_ERROR}, status=400)

    otp_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.recovery_phone, user=user)
    otp_device.generate_challenge()
    return HttpResponse()


@api_view(["POST"])
def confirm_secondary_otp(request):
    # check otp code for user
    # mark phone as confirmed on user model
    user = request.user
    if not user.recovery_phone:
        return JsonResponse({"error": NO_RECOVERY_PHONE_ERROR}, status=400)
    device, _ = PhoneDevice.objects.get_or_create(phone_number=user.recovery_phone, user=user)
    data = request.data
    verified = device.verify_token(data.get("token"))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    user.recovery_phone_validated = True
    user.recovery_phone_validation_deadline = None
    user.save()
    return HttpResponse()


@api_view(["POST"])
@authentication_classes([SessionTokenAuthentication])
def complete_profile(request):
    if not request.auth.is_phone_validated:
        return JsonResponse({"error": ErrorCodes.PHONE_NOT_VALIDATED}, status=403)

    name = request.data.get("name")
    recovery_pin = request.data.get("recovery_pin")
    photo = request.data.get("photo")
    if not (name and recovery_pin and photo):
        return JsonResponse({"error": ErrorCodes.MISSING_DATA}, status=400)

    # Deactivate any existing user with the same phone number
    ConnectUser.objects.filter(phone_number=request.auth.phone_number, is_active=True).update(is_active=False)

    session = request.auth
    device_security = ConnectUser.DeviceSecurity.PIN if session.invited_user else ConnectUser.DeviceSecurity.BIOMETRIC
    user = ConnectUser(
        username=token_hex()[:20],
        phone_number=request.auth.phone_number,
        name=name,
        phone_validated=True,
        device_security=device_security,
    )
    user.set_recovery_pin(recovery_pin)
    password = token_hex()
    user.set_password(password)

    error_code = upload_photo_to_s3(photo, user.username)
    if error_code:
        return JsonResponse({"error": error_code}, status=500)

    user.save()
    db_key = UserKey.get_or_create_key_for_user(user)
    return JsonResponse(
        {
            "username": user.username,
            "password": password,
            "db_key": db_key.key,
        }
    )


@api_view(["POST"])
@permission_classes([])
def recover_account(request):
    data = request.data
    if not data.get("phone"):
        return JsonResponse({"error": "OTP missing required key phone"}, status=400)

    user = ConnectUser.objects.get(phone_number=data["phone"], is_active=True)
    device = PhoneDevice.objects.get(phone_number=user.phone_number, user=user)
    device.generate_challenge()
    secret = token_hex()
    status, _ = RecoveryStatus.objects.get_or_create(user=user)
    status.secret_key = secret
    status.step = RecoveryStatus.RecoverySteps.CONFIRM_PRIMARY
    status.save()
    return JsonResponse({"secret": secret})


@api_view(["POST"])
@permission_classes([])
def confirm_recovery_otp(request):
    data = request.data
    required_keys = ["phone", "secret_key"]
    missing = []
    for key in required_keys:
        if key not in data:
            missing.append(key)
    if missing:
        missing_keys = ",".join(missing)
        return JsonResponse({"error": f"OTP missing required key {missing_keys}"}, status=400)
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


@api_view(["POST"])
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
    if not user.recovery_phone:
        return JsonResponse({"error": NO_RECOVERY_PHONE_ERROR}, status=400)
    otp_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.recovery_phone, user=user)
    otp_device.save()
    otp_device.generate_challenge()
    status.step = RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY
    status.save()
    return JsonResponse({"secondary_phone": user.recovery_phone.as_e164})


@api_view(["POST"])
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
    verified = device.verify_token(data.get("token"))
    if not verified:
        return JsonResponse({"error": "OTP token is incorrect"}, status=401)
    status.step = RecoveryStatus.RecoverySteps.RESET_PASSWORD
    status.save()
    db_key = UserKey.get_or_create_key_for_user(user)
    user_data = {
        "name": user.name,
        "username": user.username,
        "secondary_phone": user.recovery_phone.as_e164,
        "db_key": db_key.key,
    }
    user_data.update(user_payment_profile(user))
    return JsonResponse(user_data)


@api_view(["POST"])
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
    return JsonResponse(user_data(user))


@api_view(["POST"])
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


@api_view(["GET"])
@permission_classes([])
def phone_available(request):
    phone_number = request.query_params.get("phone_number")
    if not phone_number:
        return HttpResponse(status=400)
    try:
        ConnectUser.objects.get(phone_number=phone_number, is_active=True)
    except ConnectUser.DoesNotExist:
        return HttpResponse()
    else:
        return HttpResponse(status=403)


@api_view(["POST"])
@permission_classes([])
def change_phone(request):
    data = request.data
    user = request.user
    error = None
    if user.phone_validated:
        error = "You cannot change a validated number"
    elif user.phone_number != data["old_phone_number"]:
        error = "Old phone number does not match"
    if error:
        return JsonResponse({"error": error}, status=400)
    user.phone_number = data["new_phone_number"]

    try:
        user.full_clean()
    except ValidationError as e:
        return JsonResponse(e.message_dict, status=400)
    user.save()
    return HttpResponse()


@api_view(["POST"])
def change_password(request):
    data = request.data
    if not data.get("password"):
        return JsonResponse({"error": "No password provided"}, status=400)

    user = request.user
    password = data["password"]
    try:
        validate_password(password)
    except ValidationError:
        return JsonResponse({"error": "Password is not complex enough"}, status=400)
    user.set_password(password)
    user.save()
    return HttpResponse()


@api_view(["POST"])
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
    if data.get("photo"):
        error_code = upload_photo_to_s3(data["photo"], user.username)
        if error_code:
            return JsonResponse({"error": error_code}, status=500)
    if changed:
        try:
            user.full_clean()
        except ValidationError as e:
            return JsonResponse(e.message_dict, status=400)
        user.save()
    return HttpResponse()


@api_view(["POST"])
def set_recovery_pin(request):
    data = request.data
    user = request.user

    if not data.get("recovery_pin"):
        return JsonResponse({"error": ErrorCodes.MISSING_RECOVERY_PIN}, status=400)

    recovery_pin = data["recovery_pin"]
    user.set_recovery_pin(recovery_pin)
    user.save()
    return HttpResponse()


def user_data(user):
    db_key = UserKey.get_or_create_key_for_user(user)
    user_data = {
        "name": user.name,
        "username": user.username,
        "secondary_phone": user.recovery_phone.as_e164 if user.recovery_phone else None,
        "secondary_phone_validate_by": user.recovery_phone_validation_deadline,
        "db_key": db_key.key,
    }
    user_data.update(user_payment_profile(user))
    return user_data


def user_payment_profile(user):
    try:
        profile = user.payment_profile
        return {
            "payment_profile": {
                "phone_number": profile.phone_number.as_e164,
                "owner_name": profile.owner_name,
                "telecom_provider": profile.telecom_provider,
                "is_verified": profile.is_verified,
                "status": profile.status,
            }
        }
    except ObjectDoesNotExist:
        return {"payment_profile": {}}


@api_view(["POST"])
@permission_classes([])
def confirm_recovery_pin(request):
    data = request.data
    phone_number = data["phone"]
    secret_key = data["secret_key"]
    user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return JsonResponse({"error_code": ErrorCodes.INVALID_SECRET_KEY}, status=401)
    if status.step != RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY:
        return JsonResponse({"error_code": ErrorCodes.INVALID_STEP}, status=401)
    recovery_pin = data["recovery_pin"]

    try:
        if not user.check_recovery_pin(recovery_pin):
            return JsonResponse({"error_code": ErrorCodes.INCORRECT_CODE}, status=401)
    except RecoveryPinNotSetError:
        return JsonResponse({"error_code": ErrorCodes.NO_RECOVERY_PIN_SET}, status=400)

    status.step = RecoveryStatus.RecoverySteps.RESET_PASSWORD
    status.save()
    return JsonResponse(user_data(user))


@api_view(["POST"])
@authentication_classes([SessionTokenAuthentication])
def confirm_backup_code(request):
    session = request.auth

    if not session.is_phone_validated:
        return JsonResponse({"error_code": ErrorCodes.PHONE_NOT_VALIDATED}, status=403)

    data = request.data
    user = ConnectUser.objects.get(phone_number=session.phone_number, is_active=True)

    try:
        if not user.check_recovery_pin(data.get("recovery_pin")):
            user.add_failed_backup_code_attempt()

            if user.backup_code_attempts_left == 0:
                user.is_active = False
                user.is_locked = True
                user.save()
                return JsonResponse({"error_code": ErrorCodes.LOCKED_ACCOUNT}, status=200)

            return JsonResponse({"attempts_left": user.backup_code_attempts_left}, status=200)

    except RecoveryPinNotSetError:
        return JsonResponse({"error_code": ErrorCodes.NO_RECOVERY_PIN_SET}, status=400)

    password = token_hex(16)
    user.set_password(password)
    user.reset_failed_backup_code_attempts()
    user.save()

    return JsonResponse(
        {
            "username": user.username,
            "db_key": UserKey.get_or_create_key_for_user(user).key,
            "password": password,
        }
    )


@api_view(["GET"])
def fetch_db_key(request):
    db_key = UserKey.get_or_create_key_for_user(request.user)
    return JsonResponse({"db_key": db_key.key})


@api_view(["POST"])
def heartbeat(request):
    data = request.data
    user = request.user
    if not data.get("fcm_token"):
        return JsonResponse({}, status=200)

    fcm_token = data["fcm_token"]
    return create_update_device(user, fcm_token)


class FetchUsers(ClientProtectedResourceMixin, View):
    required_scopes = ["user_fetch"]

    def get(self, request, *args, **kwargs):
        numbers = request.GET.getlist("phone_numbers")
        results = {}
        found_users = list(
            ConnectUser.objects.filter(phone_number__in=numbers, is_active=True).values(
                "username", "phone_number", "name"
            )
        )
        results["found_users"] = found_users
        return JsonResponse(results)


class GetDemoUsers(ClientProtectedResourceMixin, View):
    required_scopes = ["user_fetch"]

    def get(self, request, *args, **kwargs):
        demo_phone_devices = PhoneDevice.objects.filter(
            phone_number__startswith=TEST_NUMBER_PREFIX,
            token__isnull=False,
        ).values("phone_number", "token")
        demo_connect_users = (
            ConnectUser.objects.filter(
                phone_number__startswith=TEST_NUMBER_PREFIX,
                deactivation_token__isnull=False,
            )
            .annotate(token=F("deactivation_token"))
            .values("phone_number", "token")
        )

        demo_users = list(demo_phone_devices) + list(demo_connect_users)
        sorted_demo_users = sorted(
            demo_users,
            key=lambda x: x["phone_number"],
        )
        results = {"demo_users": sorted_demo_users}
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
            query = query.filter(user__phone_number__startswith=country, user__is_active=True)
        users = query.select_related("user")
        user_list = [
            {"username": u.user.username, "phone_number": u.user.phone_number.as_e164, "name": u.user.name}
            for u in users
        ]
        result = {"found_users": user_list}
        return JsonResponse(result)


def get_issuing_auth(request):
    auth_header = request.headers.get("authorization")
    encoded_credentials = auth_header.split(" ")[1]
    decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
    client_id, client_secret = decoded_credentials.split(":")
    issuing_auth = IssuingAuthority.objects.get(server_credentials__client_id=client_id)
    return issuing_auth


class AddCredential(APIView):
    authentication_classes = [IssuingCredentialsAuth]

    def post(self, request, *args, **kwargs):
        creds = request.data.get("credentials")
        if not creds:
            return JsonResponse({"error_code": ErrorCodes.MISSING_DATA}, status=400)

        issuing_auth = get_issuing_auth(request)
        success_creds = []
        failed_creds = []
        for index, cred in enumerate(creds):
            try:
                credential, _ = Credential.objects.get_or_create(
                    type=cred.get("type"),
                    level=cred.get("level"),
                    issuer=issuing_auth,
                    slug=cred.get("app_id"),
                )
                credential.title = cred.get("title")
                credential.app_id = cred.get("app_id")
                credential.opportunity_id = cred.get("opportunity_id")
                credential.save()
            except (IntegrityError, AttributeError):
                failed_creds.append(index)
                continue
            success_creds.append(index)
            phone_numbers = cred.get("users", [])
            users = ConnectUser.objects.filter(phone_number__in=phone_numbers, is_active=True)
            for user in users:
                UserCredential.add_credential(user, credential, request)
        return JsonResponse({"success": success_creds, "failed": failed_creds})


class ListCredentials(APIView):
    def get(self, request, *args, **kwargs):
        credentials = Credential.objects.filter(usercredential__user=request.user)
        serializer = CredentialSerializer(credentials, many=True)
        return JsonResponse({"credentials": serializer.data})


class ForwardHQInvite(APIView):
    """
    This view gets called by CommCareHQ to invite
        a ConnectID User. It takes invite metadata
        and fowards it as a deeplink SMS to mobile
    """

    authentication_classes = [ClientProtectedResourceAuth]

    def post(self, request, *args, **kwargs):
        phone_number = request.data["phone_number"]
        callback_url = request.data["callback_url"]
        if not is_trusted_hqinvite_url(callback_url):
            return JsonResponse({"error": "Unauthorized callback URL"}, status=400)
        try:
            user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
        except ConnectUser.DoesNotExist:
            # We don't want to make this a user lookup service
            # So fake a success message
            return JsonResponse({"success": True})

        query_string = urlencode(
            {
                "hq_username": request.data["username"],
                "hq_domain": request.data["user_domain"],
                "connect_username": user.username,
                "invite_code": request.data["invite_code"],
                "callback_url": callback_url,
            }
        )
        deeplink = f"https://connectid.dimagi.com/hq_invite/?{query_string}"

        message = f"""
        You are invited to join a CommCare project ({request.data["user_domain"]})
        Please click on {deeplink} to join using your ConnectID
        account.
        Once you confirm, you will be able to login using your
        ConnectID account. Your username is ({request.data["username"]})
        Thanks.
        -The ConnectID Team.
        """
        sender = get_sms_sender(user.phone_number.country_code)
        send_sms(user.phone_number.as_e164, message, sender)
        return JsonResponse({"success": True})


def is_trusted_hqinvite_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc in settings.TRUSTED_COMMCAREHQ_HOSTS


class ConfirmHQInviteCallback(APIView):
    def post(self, request, *args, **kwargs):
        invite_code = request.data["invite_code"]
        user_token = request.data["user_token"]
        callback_url = request.data["callback_url"]

        # Validate callback_url
        if not is_trusted_hqinvite_url(callback_url):
            return JsonResponse({"error": "Unauthorized callback URL"}, status=400)

        try:
            response = requests.post(callback_url, data={"invite_code": invite_code, "token": user_token})
            response.raise_for_status()
        except requests.RequestException:
            return JsonResponse({"error": "Failed to reach callback URL"}, status=500)
        return JsonResponse({"success": True})


@api_view(["GET"])
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


@api_view(["POST"])
@permission_classes([])
def initiate_deactivation(request):
    data = request.data
    phone_number = data["phone_number"]
    secret_key = data["secret_key"]
    try:
        user = ConnectUser.objects.get(phone_number=phone_number, is_active=True)
    except ConnectUser.DoesNotExist:
        return JsonResponse({"error_code": ErrorCodes.USER_DOES_NOT_EXIST}, status=400)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return JsonResponse({"error_code": ErrorCodes.INVALID_SECRET_KEY}, status=401)
    user.initiate_deactivation()
    return HttpResponse()


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
        return JsonResponse({"error_code": ErrorCodes.USER_DOES_NOT_EXIST}, status=400)
    status = RecoveryStatus.objects.get(user=user)
    if status.secret_key != secret_key:
        return JsonResponse({"error_code": ErrorCodes.INVALID_SECRET_KEY}, status=401)
    if user.deactivation_token != deactivation_token:
        return JsonResponse({"error_code": ErrorCodes.INVALID_TOKEN}, status=401)
    if user.deactivation_token_valid_until < now():
        return JsonResponse({"error_code": ErrorCodes.TOKEN_EXPIRED}, status=401)
    user.is_active = False
    user.save()
    tokens = list(AccessToken.objects.filter(user=user)) + list(RefreshToken.objects.filter(user=user))
    for token in tokens:
        token.revoke()
    return HttpResponse()


class FetchUserCounts(ClientProtectedResourceMixin, View):
    required_scopes = ["user_fetch"]

    def get(self, request, *args, **kwargs):
        counts = (
            ConnectUser.objects.annotate(date_joined_month=TruncMonth("date_joined"))
            .values("date_joined_month")
            .annotate(monthly_count=Count("*"))
        )
        count_by_year_month = {item["date_joined_month"].strftime("%Y-%m"): item["monthly_count"] for item in counts}
        return JsonResponse(count_by_year_month)


@api_view(["POST"])
@authentication_classes([SessionTokenAuthentication])
def check_user_similarity(request):
    name = request.data.get("name")
    if not name:
        return JsonResponse({"error_code": ErrorCodes.NAME_REQUIRED}, status=400)

    if not request.auth.is_phone_validated:
        return JsonResponse({"error_code": ErrorCodes.PHONE_NOT_VALIDATED}, status=403)

    existing_user = None
    try:
        existing_user = ConnectUser.objects.get(phone_number=request.auth.phone_number, is_active=True)
    except ConnectUser.DoesNotExist:
        pass

    is_same_user = False

    if existing_user:
        is_same_user = True  # assume true until proven otherwise, because user owns this number
        user_name_is_similar = OpenChatStudio().check_name_similarity(
            reference_name=existing_user.name,
            candidate_name=name,
            cultural_context=request.auth.phone_number.country_code,
        )

        # For now we don't do anything with the response for Connect users
        if not request.auth.invited_user and user_name_is_similar is not None:
            is_same_user = user_name_is_similar

    return JsonResponse(
        {
            "account_exists": is_same_user,
            "photo": existing_user.get_photo() if is_same_user else "",
        }
    )


@api_view(["POST"])
@authentication_classes([SessionTokenAuthentication])
def send_session_otp(request):
    otp_device, _ = SessionPhoneDevice.objects.get_or_create(
        phone_number=request.auth.phone_number, session=request.auth
    )
    otp_device.generate_challenge()
    return HttpResponse()


@api_view(["POST"])
@authentication_classes([SessionTokenAuthentication])
def confirm_session_otp(request):
    device = SessionPhoneDevice.objects.get(phone_number=request.auth.phone_number, session=request.auth)
    data = request.data
    verified = device.verify_token(data.get("otp"))
    if not verified:
        return JsonResponse({"error": ErrorCodes.INCORRECT_OTP}, status=401)
    request.auth.is_phone_validated = True
    request.auth.save()
    if device.has_manual_otp:
        device.has_manual_otp = False
        device.save()
    return HttpResponse()


@api_view(["POST"])
@permission_classes([])
def report_integrity(request):
    data = request.data
    request_id = data.get("request_id")
    device_id = data.get("cc_device_id")

    if not (request_id and device_id):
        return JsonResponse({"error_code": ErrorCodes.MISSING_DATA}, status=400)

    integrity_token = request.headers.get("CC-Integrity-Token")
    request_hash = request.headers.get("CC-Request-Hash")

    if not integrity_token or not request_hash:
        return JsonResponse({"error_code": ErrorCodes.MISSING_DATA}, status=400)

    # This is for testing with demo users or test apps
    app_package = data.get("application_id")
    phone_number = data.get("phone_number", "")
    is_demo_user = phone_number.startswith(TEST_NUMBER_PREFIX)

    service = AppIntegrityService(
        token=integrity_token,
        request_hash=request_hash,
        app_package=app_package,
        is_demo_user=is_demo_user,
    )

    try:
        sample = service.log_sample_request(
            request_id=request_id,
            device_id=device_id,
        )
    except DuplicateSampleRequestError:
        return JsonResponse({"result_code": None}, status=200)
    except HttpError:
        return JsonResponse({"result_code": None}, status=500)

    return JsonResponse({"result_code": "passed" if sample.passed else "failed"})


class GenerateManualOTP(APIView):
    authentication_classes = [ClientProtectedResourceAuth]

    def get(self, request, *args, **kwargs):
        phone_number = request.query_params.get("phone_number")
        if not phone_number:
            return JsonResponse({"error_code": ErrorCodes.MISSING_DATA}, status=400)

        session_phone_device = (
            SessionPhoneDevice.objects.filter(phone_number=phone_number).order_by("-session__created").first()
        )
        if not (session_phone_device and session_phone_device.session.is_valid()):
            return JsonResponse({"error_code": ErrorCodes.SESSION_NOT_FOUND}, status=404)

        session_phone_device.valid_until = now() + timedelta(hours=4)
        session_phone_device.has_manual_otp = True
        session_phone_device.save()

        session_phone_device.session.expires = session_phone_device.valid_until
        session_phone_device.session.save()

        return JsonResponse({"otp": session_phone_device.token})
