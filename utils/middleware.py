import base64
import json
import logging

import sentry_sdk
from rest_framework.settings import api_settings

from users.const import ErrorCodes

logger = logging.getLogger(__name__)


class CurrentVersionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.include_version_headers = False
        response = self.get_response(request)
        if request.include_version_headers:
            response.headers["X-API-Current-Version"] = api_settings.DEFAULT_VERSION

        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if hasattr(view_func, "cls") and view_func.cls.versioning_class is not None:
            request.include_version_headers = True


# 401s that are a normal part of the app's flows: the user typed a wrong code, a session ran out, the
# account is locked, or the request carried no credentials at all (mostly crawlers). Everything else,
# such as device credentials or a recovery secret key the app manages being rejected, should not happen.
EXPECTED_401_REASONS = {
    ErrorCodes.TOKEN_EXPIRED,
    ErrorCodes.INCORRECT_OTP,
    ErrorCodes.OTP_LIMIT_EXCEEDED,
    ErrorCodes.INCORRECT_CODE,
    ErrorCodes.LOCKED_ACCOUNT,
    ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE,
    ErrorCodes.ACTIVE_USER_EXISTS,
    "OTP token is incorrect",
    "not_authenticated",
}


class Log401ErrorsMiddleware:
    """Log every 401 with its reason, and report the unexpected ones to Sentry.

    A line is `auth_401 reason=... path=... scheme=...`. Expected reasons are logged at INFO; any other is
    logged at ERROR, which the Sentry logging integration turns into an event, one issue per reason and path.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if response.status_code == 401:
            self._log(request, response)
        return response

    def _log(self, request, response):
        reason = _401_reason(response) or "unknown"
        scheme, username = _auth_scheme_and_username(request)
        match = getattr(request, "resolver_match", None)
        path = f"/{match.route}" if match and match.route else request.path
        fields = {"reason": reason, "path": path, "scheme": scheme}
        message = " ".join(["auth_401", *(f"{name}={value}" for name, value in fields.items())])
        level = logging.INFO if reason in EXPECTED_401_REASONS else logging.ERROR
        with sentry_sdk.new_scope() as scope:
            for name, value in fields.items():
                scope.set_tag(f"auth_401.{name}", value)
            if username:
                scope.set_user({"username": username})
            logger.log(level, message, extra={"auth_401": fields})


def _401_reason(response):
    """The error code or message a 401 response carries, whether DRF or a plain JsonResponse built it."""
    data = getattr(response, "data", None)
    if data is None and not response.streaming and response.get("Content-Type", "").startswith("application/json"):
        try:
            data = json.loads(response.content)
        except ValueError:
            return None
    if not isinstance(data, dict):
        return None
    for key in ("error_code", "error"):
        if isinstance(data.get(key), str):
            return str(data[key])
    detail = data.get("detail")
    if detail is not None:
        # DRF's own failures: `not_authenticated` (no credentials) or `authentication_failed` (wrong ones)
        return getattr(detail, "code", None) or str(detail)
    return None


def _auth_scheme_and_username(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return "none", None
    scheme = auth_header.split(" ", 1)[0]
    if scheme != "Basic":
        return (scheme if scheme in ("Bearer", "Token") else "other"), None
    try:
        decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
    except (IndexError, ValueError):
        return "Basic(malformed)", None
    username, sep, _ = decoded.partition(":")
    return ("Basic", username) if sep else ("Basic(malformed)", None)
