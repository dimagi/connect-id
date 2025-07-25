import logging

from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseServerError, JsonResponse
from googleapiclient.errors import HttpError

from users.const import TEST_NUMBER_PREFIX
from utils.app_integrity.const import INTEGRITY_REQUEST_HASH_KEY, INTEGRITY_TOKEN_HEADER_KEY, ErrorCodes
from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.google_play_integrity import AppIntegrityService
from utils.connect import check_number_for_existing_invites

logger = logging.getLogger(__name__)


def validate_app_integrity(integrity_token, request_hash, app_package, phone_number):
    logging_prefix = f"App integrity error for ...{phone_number[-6:]}"

    if not (integrity_token and request_hash):
        logger.info(f"{logging_prefix}: missing integrity token or request hash in headers")
        return JsonResponse(
            {"error_code": ErrorCodes.MISSING_DATA, "error_sub_code": "INTEGRITY_HEADERS"},
            status=HttpResponseBadRequest.status_code,
        )

    is_demo_user = phone_number.startswith(TEST_NUMBER_PREFIX)

    service = AppIntegrityService(
        token=integrity_token,
        request_hash=request_hash,
        app_package=app_package,
        is_demo_user=is_demo_user,
    )
    try:
        service.verify_integrity()
    except (IntegrityRequestError, AccountDetailsError, AppIntegrityError, DeviceIntegrityError) as e:
        logger.info(f"{logging_prefix}: {str(e)}")
        response = {
            "error_code": ErrorCodes.INTEGRITY_ERROR,
            "error_sub_code": e.code,
        }
        return JsonResponse(response, status=HttpResponseForbidden.status_code)
    except HttpError:
        logger.info(f"{logging_prefix}: Google Play Integrity API not available")
        return JsonResponse(
            {"error_code": ErrorCodes.INTEGRITY_SERVICE_UNAVAILABLE}, status=HttpResponseServerError.status_code
        )


def require_app_integrity(view):
    """
    Checks the integrity of the app using the Google Play Integrity API.
    """

    def wrapper(request, *args, **kwargs):
        integrity_token = request.headers.get(INTEGRITY_TOKEN_HEADER_KEY)
        request_hash = request.headers.get(INTEGRITY_REQUEST_HASH_KEY)
        phone_number = request.data.get("phone_number", "")

        invited = check_number_for_existing_invites(phone_number)
        request.invited_user = invited

        app_package = request.data.get("application_id")
        error_response = validate_app_integrity(integrity_token, request_hash, app_package, phone_number)
        if error_response is not None and not invited:
            return error_response

        return view(request, *args, **kwargs)

    return wrapper
