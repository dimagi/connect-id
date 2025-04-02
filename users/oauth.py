from oauth2_provider.oauth2_validators import OAuth2Validator


class ConnectOAuth2Validator(OAuth2Validator):
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update({"is_active": "openid", "phone": "openid", "name": "openid"})

    def get_additional_claims(self, request):
        claims = {}
        claims["sub"] = request.user.username
        claims["name"] = request.user.name
        claims["phone"] = request.user.phone_number.as_e164
        claims["is_active"] = request.user.is_active
        return claims
