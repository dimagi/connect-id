from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from users.models import ConfigurationSession, SessionUser


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
        if token.backup_code_attempts_left == 0:
            raise exceptions.AuthenticationFailed("Backup code attempts exceeded.")
        user = SessionUser()
        return (user, token)
