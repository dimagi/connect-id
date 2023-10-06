from django.contrib.auth.models import AnonymousUser
from oauth2_provider.views.mixins import OAuthLibMixin
from rest_framework.authentication import BaseAuthentication


class ClientProtectedResourceAuth(OAuthLibMixin, BaseAuthentication):
    """Authenticate request using Client credentials (as in the OAuth2 spec).
    """

    def authenticate(self, request):
        # Validate either with HTTP basic or client creds in request body.
        valid = self.authenticate_client(request)
        if not valid:
            # Alternatively allow access tokens
            # check if the request is valid and the protected resource may be accessed
            valid, r = self.verify_request(request)
            if valid:
                request.resource_owner = r.user
                return r.user, r.access_token
            return None
        else:
            return OauthClientUser(), None


class OauthClientUser(AnonymousUser):
    """Fake user used for requests authenticated via Client credentials"""
    def is_authenticated(self):
        return True

    def __str__(self):
        return "OauthClientUser"
