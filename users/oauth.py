from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749.errors import OAuth2Error

from users.const import ErrorCodes
from users.device_utils import check_login_from_different_device, update_device_last_accessed
from users.models import ConnectUser


class LoginFromDifferentDeviceError(OAuth2Error):
    error = ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE
    description = "Login attempted from a previously configured device."

    @property
    def twotuples(self):
        return super().twotuples + [("error_code", self.error)]


class ConnectOAuth2Validator(OAuth2Validator):
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update({"is_active": "openid", "phone": "openid", "name": "openid"})

    def validate_user(self, username, password, client, request, *args, **kwargs):
        result = super().validate_user(username, password, client, request, *args, **kwargs)
        if result:
            update_device_last_accessed(request.user, password)
        else:
            try:
                user = ConnectUser.objects.get(username=username, is_active=True)
            except ConnectUser.DoesNotExist:
                return result
            if check_login_from_different_device(user, password):
                raise LoginFromDifferentDeviceError()
        return result

    def get_additional_claims(self, request):
        claims = {}
        claims["sub"] = request.user.username
        claims["name"] = request.user.name
        claims["phone"] = request.user.phone_number.as_e164
        claims["is_active"] = request.user.is_active
        return claims
