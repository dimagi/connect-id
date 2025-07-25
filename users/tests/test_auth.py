import pytest
from rest_framework import exceptions
from rest_framework.test import APIRequestFactory

from users.const import ErrorCodes
from users.models import SessionUser


@pytest.mark.django_db
class TestSessionTokenAuthentication:
    def test_authentication_valid_token(self, token_auth, valid_token):
        request = APIRequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {valid_token.key}")
        user, token = token_auth.authenticate(request)
        assert token == valid_token
        assert isinstance(user, SessionUser)
        assert request.headers["authorization"] == f"Bearer {valid_token.key}"

    def test_authentication_expired_token(self, token_auth, expired_token):
        request = APIRequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {expired_token.key}")
        with pytest.raises(exceptions.AuthenticationFailed) as excinfo:
            token_auth.authenticate(request)
        assert excinfo.value.detail == {"error_code": ErrorCodes.TOKEN_EXPIRED}

    def test_authentication_invalid_token(self, token_auth):
        request = APIRequestFactory().get("/", HTTP_AUTHORIZATION="Bearer invalid_token")
        with pytest.raises(exceptions.AuthenticationFailed) as excinfo:
            token_auth.authenticate(request)
        assert excinfo.value.detail == {"error_code": ErrorCodes.INVALID_TOKEN}

    def test_authentication_missing_auth_header(self, token_auth):
        request = APIRequestFactory().get("/")
        result = token_auth.authenticate(request)
        assert result is None

    def test_no_backup_code_attempts_left(self, token_auth, valid_token, user):
        user.is_locked = True
        user.is_active = False
        user.save()
        request = APIRequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {valid_token.key}")
        with pytest.raises(exceptions.AuthenticationFailed) as excinfo:
            token_auth.authenticate(request)
        assert excinfo.value.detail == {"error_code": ErrorCodes.LOCKED_ACCOUNT}
