import logging
import re
import time
from urllib.parse import unquote_plus

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
    """Log one line per request: `request method=... route=... query=... status=... duration_ms=... user_id=...`.

    Nothing the caller sent is logged as is, so tokens, phone numbers and forged log lines stay out:
    - `route` is the matched URL pattern (`/users/accept_credential/<slug:invite_id>`), or `<unresolved>`
      when no pattern matches, never the path.
    - `query` is the names of the query parameters, never their values. A name that isn't a plain
      identifier is logged as `?`, and only the first `MAX_QUERY_PARAMS` names are kept.
    `/up` is skipped: it is the liveness probe and would drown out the rest.
    """

    SKIPPED_URL_NAMES = {"up"}
    UNRESOLVED_ROUTE = "<unresolved>"
    MAX_QUERY_PARAMS = 20
    _SAFE_PARAM_NAME = re.compile(r"[A-Za-z0-9_.\-\[\]]{1,64}")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.monotonic()
        response = self.get_response(request)
        if not request_logger.isEnabledFor(logging.INFO):
            return response
        duration_ms = round((time.monotonic() - start) * 1000)

        match = request.resolver_match
        if match is not None and match.url_name in self.SKIPPED_URL_NAMES:
            return response

        user = getattr(request, "user", None)
        fields = {
            "method": request.method,
            "route": f"/{match.route}" if match is not None else self.UNRESOLVED_ROUTE,
            "query": self._query_param_names(request),
            "status": response.status_code,
            "duration_ms": duration_ms,
            "user_id": user.pk if user is not None and user.is_authenticated else None,
        }
        message = " ".join(["request", *(f"{name}={value}" for name, value in fields.items())])
        request_logger.info(message, extra={"request_log": fields})
        return response

    def _query_param_names(self, request) -> str:
        # Parsed from the raw query string, not request.GET: that raises TooManyFieldsSent past
        # DATA_UPLOAD_MAX_NUMBER_FIELDS, which would turn the response into a 400.
        names = []
        for pair in request.META.get("QUERY_STRING", "").split("&"):
            if len(names) == self.MAX_QUERY_PARAMS:
                break
            name = unquote_plus(pair.partition("=")[0])
            if not name:
                continue
            name = name if self._SAFE_PARAM_NAME.fullmatch(name) else "?"
            if name == "?" or name not in names:
                names.append(name)
        return ",".join(names)
