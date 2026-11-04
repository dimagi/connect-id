import hmac

from django.conf import settings
from django.http import Http404, HttpResponse, JsonResponse
from django.views.decorators.cache import never_cache
from health_check.views import HealthCheckView

from .health_checks import CHECK_SUBSETS


def assetlinks_json(request):
    assetfile = [
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "org.commcare.dalvik",
                "sha256_cert_fingerprints": [
                    "88:57:18:F8:E8:7D:74:04:97:AE:83:65:74:ED:EF:10:40:D9:4C:E2:54:F0:E0:40:64:77:96:7F:D1:39:F9:81",
                    "89:55:DF:D8:0E:66:63:06:D2:6D:88:A4:A3:88:A4:D9:16:5A:C4:1A:7E:E1:C6:78:87:00:37:55:93:03:7B:03",
                ],
            },
        },
        {
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "org.commcare.dalvik.debug",
                "sha256_cert_fingerprints": [
                    "88:57:18:F8:E8:7D:74:04:97:AE:83:65:74:ED:EF:10:40:D9:4C:E2:54:F0:E0:40:64:77:96:7F:D1:39:F9:81"
                ],
            },
        },
    ]
    return JsonResponse(assetfile, safe=False)


@never_cache
def up(request):
    """Liveness probe for the container health check.

    Only shows that Django is serving requests: it touches no database or other service, so an
    outage elsewhere does not get a healthy container restarted. Use /status/ for dependencies.
    """
    return HttpResponse("OK", content_type="text/plain")


class HealthCheck(HealthCheckView):
    """Dependency health for the status page: /status/ and /status/<subset>/.

    When ``HEALTH_CHECK_TOKENS`` is set, a request must pass ``?token=`` matching one of them. A
    missing or wrong token, like an unknown subset, gets a 404 so the endpoint does not reveal itself.
    """

    async def dispatch(self, request, *args, subset="general", **kwargs):
        if not _has_valid_token(request) or subset not in CHECK_SUBSETS:
            raise Http404
        self.checks = CHECK_SUBSETS[subset]
        return await super().dispatch(request, *args, **kwargs)


def _has_valid_token(request):
    tokens = settings.HEALTH_CHECK_TOKENS
    if not tokens:
        return True
    given = request.GET.get("token", "")
    # Compare against every token, without stopping early, so timing does not reveal a match.
    matches = [hmac.compare_digest(given.encode(), token.encode()) for token in tokens]
    return any(matches)
