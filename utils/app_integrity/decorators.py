from django.http import JsonResponse

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
        integrity_token = request.POST.get("integrity_token")
        request_hash = request.POST.get("request_hash")

        if not (integrity_token and request_hash):
            return JsonResponse({"error_code": "INTEGRITY_TOKEN_MISSING"}, status=400)

        service = AppIntegrityService(token=integrity_token, request_hash=request_hash)
        try:
            service.verify_integrity()
        except AccountDetailsError:
            return JsonResponse({"error_code": "UNLICENSED_APP"}, status=400)
        except (IntegrityRequestError, AppIntegrityError, DeviceIntegrityError):
            return JsonResponse({"error_code": "INTEGRITY_ERROR"}, status=400)

        return view(request, *args, **kwargs)

    return wrapper
