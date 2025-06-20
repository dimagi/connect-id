import logging

from django.http import HttpResponseBadRequest, HttpResponseForbidden, JsonResponse

from users.const import TEST_NUMBER_PREFIX
from utils.app_integrity.const import INTEGRITY_REQUEST_HASH_KEY, INTEGRITY_TOKEN_HEADER_KEY, ErrorCodes
from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.google_play_integrity import AppIntegrityService

logger = logging.getLogger(__name__)


def require_app_integrity(view):
    """
    Checks the integrity of the app using the Google Play Integrity API.
    """

    def wrapper(request, *args, **kwargs):
        integrity_token = request.headers.get(INTEGRITY_TOKEN_HEADER_KEY)
        request_hash = request.headers.get(INTEGRITY_REQUEST_HASH_KEY)
        phone_number = request.data.get("phone_number", "")

        logging_prefix = f"App integrity error for {phone_number}"

        if not (integrity_token and request_hash):
            logger.exception(f"{logging_prefix}: missing integrity token or request hash in headers")
            return JsonResponse(
                {"error_code": ErrorCodes.INTEGRITY_DATA_MISSING}, status=HttpResponseBadRequest.status_code
            )

        data = request.data
        is_demo_user = phone_number.startswith(TEST_NUMBER_PREFIX)

        service = AppIntegrityService(
            token=integrity_token,
            request_hash=request_hash,
            app_package=data.get("application_id"),
            is_demo_user=is_demo_user,
        )
        try:
            service.verify_integrity()
        except AccountDetailsError as e:
            logger.exception(f"{logging_prefix}: {str(e)}")
            return JsonResponse({"error_code": ErrorCodes.UNLICENSED_APP}, status=HttpResponseForbidden.status_code)
        except (IntegrityRequestError, AppIntegrityError, DeviceIntegrityError) as e:
            logger.exception(f"{logging_prefix}: {str(e)}")
            return JsonResponse({"error_code": ErrorCodes.INTEGRITY_ERROR}, status=HttpResponseForbidden.status_code)

        return view(request, *args, **kwargs)

    return wrapper
