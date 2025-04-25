from django.http import JsonResponse

from utils.app_integrity.const import INTEGRITY_REQUEST_HASH_KEY, INTEGRITY_TOKEN_HEADER_KEY, ErrorCodes
from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.google_play_integrity import AppIntegrityService


def require_integrity_check(view):
    """
    Checks the integrity of the app using the Google Play Integrity API.
    """

    def wrapper(request, *args, **kwargs):
        if request.version == "1.0":
            return view(request, *args, **kwargs)

        integrity_token = request.headers.get(INTEGRITY_TOKEN_HEADER_KEY)
        request_hash = request.headers.get(INTEGRITY_REQUEST_HASH_KEY)

        if not (integrity_token and request_hash):
            return JsonResponse({"error_code": ErrorCodes.INTEGRITY_DATA_MISSING}, status=400)

        service = AppIntegrityService(token=integrity_token, request_hash=request_hash)
        try:
            service.verify_integrity()
        except AccountDetailsError:
            return JsonResponse({"error_code": ErrorCodes.UNLICENSED_APP}, status=400)
        except (IntegrityRequestError, AppIntegrityError, DeviceIntegrityError):
            return JsonResponse({"error_code": ErrorCodes.INTEGRITY_ERROR}, status=400)

        return view(request, *args, **kwargs)

    return wrapper
