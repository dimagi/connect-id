from django.http import HttpResponseForbidden, JsonResponse

from users.const import TEST_NUMBER_PREFIX
from utils.app_integrity.const import INTEGRITY_REQUEST_HASH_KEY, INTEGRITY_TOKEN_HEADER_KEY, ErrorCodes
from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.google_play_integrity import AppIntegrityService


def require_app_integrity(view):
    """
    Checks the integrity of the app using the Google Play Integrity API.
    """

    def wrapper(request, *args, **kwargs):
        integrity_token = request.headers.get(INTEGRITY_TOKEN_HEADER_KEY)
        request_hash = request.headers.get(INTEGRITY_REQUEST_HASH_KEY)

        if not (integrity_token and request_hash):
            return JsonResponse(
                {"error_code": ErrorCodes.INTEGRITY_DATA_MISSING}, status=HttpResponseForbidden.status_code
            )

        data = request.data
        is_demo_user = data.get("phone_number", "").startswith(TEST_NUMBER_PREFIX)

        service = AppIntegrityService(
            token=integrity_token,
            request_hash=request_hash,
            app_package=data.get("application_id"),
            is_demo_user=is_demo_user,
        )
        try:
            service.verify_integrity()
        except AccountDetailsError:
            return JsonResponse({"error_code": ErrorCodes.UNLICENSED_APP}, status=HttpResponseForbidden.status_code)
        except (IntegrityRequestError, AppIntegrityError, DeviceIntegrityError):
            return JsonResponse({"error_code": ErrorCodes.INTEGRITY_ERROR}, status=HttpResponseForbidden.status_code)

        return view(request, *args, **kwargs)

    return wrapper
