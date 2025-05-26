from django.contrib.auth.models import User
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from users.models import ConfigurationSession


class SessionTokenAuthentication(TokenAuthentication):
    keyword = "Bearer"
    model = ConfigurationSession

    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid token.")
        if not token.is_valid():
            raise exceptions.AuthenticationFailed("Token expired.")
        user = User(username="annonymous")
        return (user, token)
