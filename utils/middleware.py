import logging
import time

from rest_framework.settings import api_settings

request_logger = logging.getLogger("connectid.requests")


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


class RequestLoggingMiddleware:
    """Log one line per request: `request method=... route=... status=... duration_ms=... user_id=...`.

    The route is the matched URL pattern (`accept_credential/<slug:invite_id>`), not the path, and the
    query string is left out, so tokens and other identifiers in URLs are not logged. A path that matches
    no route is logged as is. `/up` is skipped: it is the liveness probe and would drown out the rest.
    """

    SKIPPED_URL_NAMES = {"up"}

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.monotonic()
        response = self.get_response(request)
        duration_ms = round((time.monotonic() - start) * 1000)

        match = request.resolver_match
        if match is not None and match.url_name in self.SKIPPED_URL_NAMES:
            return response

        user = getattr(request, "user", None)
        fields = {
            "method": request.method,
            "route": f"/{match.route}" if match is not None else request.path,
            "status": response.status_code,
            "duration_ms": duration_ms,
            "user_id": user.pk if user is not None and user.is_authenticated else None,
        }
        message = " ".join(["request", *(f"{name}={value}" for name, value in fields.items())])
        request_logger.info(message, extra={"request_log": fields})
        return response
