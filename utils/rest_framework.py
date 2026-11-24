from django.contrib.auth.models import AnonymousUser
from oauth2_provider.views.mixins import OAuthLibMixin
from oauthlib.common import Request as OauthlibRequest
from rest_framework.authentication import BaseAuthentication, BasicAuthentication
from rest_framework.throttling import UserRateThrottle

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


class ServiceAwareUserRateThrottle(UserRateThrottle):
    """UserRateThrottle that gives each service caller (ServiceUser) its own bucket.

    DRF keys an authenticated caller on `user.pk`, which is None for every ServiceUser, so without this
    all message servers and client-credential callers would share one bucket.
    """

    def get_cache_key(self, request, view):
        ident = getattr(request.user, "throttle_ident", None)
        if ident is None:
            return super().get_cache_key(request, view)
        return self.cache_format % {"scope": self.scope, "ident": ident}
