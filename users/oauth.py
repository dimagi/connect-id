from oauth2_provider.oauth2_validators import OAuth2Validator

class ConnectOAuth2Validator(OAuth2Validator):

    def get_additional_claims(self, request):
        claims = {}
        claims["sub"] = request.user.username
        claims["name"] = request.user.name
        claims["phone"] = request.user.phone_number
        return claims

