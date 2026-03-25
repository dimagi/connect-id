from rest_framework import exceptions
from rest_framework.authentication import BasicAuthentication, TokenAuthentication

from users.const import ErrorCodes
from users.device_utils import check_login_from_different_device, update_device_last_accessed
from users.models import ConfigurationSession, ConnectUser, IssuingAuthority, SessionUser
from utils.rest_framework import OauthClientUser


class SessionTokenAuthentication(TokenAuthentication):
    keyword = "Bearer"
    model = ConfigurationSession

    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed({"error_code": ErrorCodes.INVALID_TOKEN})
        if not token.is_valid():
            raise exceptions.AuthenticationFailed({"error_code": ErrorCodes.TOKEN_EXPIRED})
        locked_user_exists = ConnectUser.objects.filter(
            phone_number=token.phone_number, is_active=False, is_locked=True
        ).exists()
        if locked_user_exists:
            raise exceptions.AuthenticationFailed({"error_code": ErrorCodes.LOCKED_ACCOUNT})
        user = SessionUser()
        return (user, token)


class DeviceBasicAuthentication(BasicAuthentication):
    def authenticate_credentials(self, userid, password, request=None):
        try:
            result = super().authenticate_credentials(userid, password, request)
        except exceptions.AuthenticationFailed as original_exc:
            try:
                user = ConnectUser.objects.get(username=userid, is_active=True)
            except ConnectUser.DoesNotExist:
                raise original_exc from None
            if check_login_from_different_device(user, password):
                raise exceptions.AuthenticationFailed({"error_code": ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE})
            raise

        user = result[0]
        update_device_last_accessed(user, password)
        return result


class IssuingCredentialsAuth(BasicAuthentication):
    def authenticate_credentials(self, userid, password, request=None):
        try:
            issuing_auth = IssuingAuthority.objects.get(server_credentials__client_id=userid)
        except IssuingAuthority.DoesNotExist:
            raise exceptions.AuthenticationFailed({"error_code": ErrorCodes.INVALID_CREDENTIALS})
        valid = password == issuing_auth.server_credentials.secret_key
        if valid:
            return OauthClientUser(), None
