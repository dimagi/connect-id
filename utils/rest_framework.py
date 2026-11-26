from django.contrib.auth.models import AnonymousUser
from django.core.cache import caches
from oauth2_provider.views.mixins import OAuthLibMixin
from oauthlib.common import Request as OauthlibRequest
from rest_framework.authentication import BaseAuthentication, BasicAuthentication
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from messaging.models import MessageServer


class ClientProtectedResourceAuth(OAuthLibMixin, BaseAuthentication):
    """Authenticate request using Client credentials (as in the OAuth2 spec)."""

    def authenticate(self, request):
        # Validate either with HTTP basic or client creds in request body. Done here rather than through
        # OAuthLibMixin.authenticate_client so the authenticated Application is kept: the validator sets it
        # on the oauthlib request, which that method discards.
        core = self.get_oauthlib_core()
        uri, http_method, body, headers = core._extract_params(request)
        oauthlib_request = OauthlibRequest(uri, http_method, body, headers)
        if core.server.request_validator.authenticate_client(oauthlib_request):
            return OauthClientUser(f"oauth_client:{oauthlib_request.client.pk}"), None


class ServiceUser(AnonymousUser):
    """Fake user for a request authenticated as a service rather than a person.

    It has no pk. `throttle_ident` names the caller, so each one gets its own throttle bucket
    (see ServiceAwareUserRateThrottle) rather than all of them sharing the one keyed on pk None.
    """

    def __init__(self, throttle_ident):
        self.throttle_ident = throttle_ident

    @property
    def is_authenticated(self):
        return True


class OauthClientUser(ServiceUser):
    """Fake user used for requests authenticated via Client credentials"""

    def __str__(self):
        return "OauthClientUser"


class IssuingAuthorityUser(ServiceUser):
    """Fake user used for requests authenticated as a credential issuing authority"""

    def __str__(self):
        return "IssuingAuthorityUser"


class MessagingServerAuth(BasicAuthentication):
    """Authenticate request using Client credentials (as in the OAuth2 spec)."""

    def authenticate_credentials(self, userid, password, request=None):
        try:
            message_server = MessageServer.objects.get(server_credentials__client_id=userid)
        except MessageServer.DoesNotExist:
            return None
        valid = password == message_server.server_credentials.secret_key
        if valid:
            return MessagingServerUser(f"message_server:{message_server.pk}"), None


class MessagingServerUser(ServiceUser):
    """Fake user used for requests authenticated via Client credentials"""

    def __str__(self):
        return "MessagingServerUser"


THROTTLE_CACHE_ALIAS = "throttle"


class SharedCacheThrottleMixin:
    """Keep throttle history in the shared "throttle" cache instead of DRF's default, the per-process
    "default" cache, so a limit counts a caller's requests across every worker and host."""

    @property
    def cache(self):
        return caches[THROTTLE_CACHE_ALIAS]


class SharedAnonRateThrottle(SharedCacheThrottleMixin, AnonRateThrottle):
    pass


class ServiceAwareUserRateThrottle(SharedCacheThrottleMixin, UserRateThrottle):
    """UserRateThrottle that gives each fake user its own bucket.

    DRF keys an authenticated caller on `user.pk`, which is None for every fake user (ServiceUser,
    users.models.SessionUser), so without this all of them would share one bucket. A fake user is keyed on
    its `throttle_ident`, or on the client's address if it has none.
    """

    def get_cache_key(self, request, view):
        user = request.user
        ident = getattr(user, "throttle_ident", None)
        if ident is None and user and user.is_authenticated and user.pk is None:
            # A fake user that names no caller: per client, never the one bucket keyed on pk None
            ident = f"unidentified:{self.get_ident(request)}"
        if ident is None:
            return super().get_cache_key(request, view)
        return self.cache_format % {"scope": self.scope, "ident": ident}
