from django.contrib.auth.models import AnonymousUser
from oauth2_provider.views.mixins import OAuthLibMixin
from rest_framework.authentication import BaseAuthentication, BasicAuthentication

from messaging.models import MessageServer


class ClientProtectedResourceAuth(OAuthLibMixin, BaseAuthentication):
    """Authenticate request using Client credentials (as in the OAuth2 spec)."""

    def authenticate(self, request):
        # Validate either with HTTP basic or client creds in request body.
        valid = self.authenticate_client(request)
        if valid:
            return OauthClientUser(), None


class OauthClientUser(AnonymousUser):
    """Fake user used for requests authenticated via Client credentials"""

    def is_authenticated(self):
        return True

    def __str__(self):
        return "OauthClientUser"


class MessagingServerAuth(BasicAuthentication):
    """Authenticate request using Client credentials (as in the OAuth2 spec)."""

    def authenticate_credentials(self, userid, password, request=None):
        try:
            server = MessageServer.objects.get(server_id=userid)
        except MessageServer.DoesNotExist:
            return None
        valid = password == server.secret_key
        if valid:
            return MessagingServerUser(), None


class MessagingServerUser(AnonymousUser):
    """Fake user used for requests authenticated via Client credentials"""

    def is_authenticated(self):
        return True

    def __str__(self):
        return "MessagingServerUser"
