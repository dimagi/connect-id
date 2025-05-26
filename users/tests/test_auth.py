from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework import exceptions
from rest_framework.test import APIRequestFactory

from users.auth import SessionTokenAuthentication
from users.factories import ConfigurationSessionFactory


@pytest.fixture
def token_auth():
    return SessionTokenAuthentication()


@pytest.fixture
def valid_token():
    return ConfigurationSessionFactory()


@pytest.fixture
def expired_token():
    expires = timezone.now() - timedelta(days=2)
    return ConfigurationSessionFactory(expires=expires)


@pytest.mark.django_db
class TestSessionTokenAuthentication:
    def test_authentication_valid_token(self, token_auth, valid_token):
        request = APIRequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {valid_token.key}")
        user, token = token_auth.authenticate(request)
        assert token == valid_token
        assert user.username == "annonymous"
        assert request.headers["authorization"] == f"Bearer {valid_token.key}"

    def test_authentication_expired_token(self, token_auth, expired_token):
        request = APIRequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {expired_token.key}")
        with pytest.raises(exceptions.AuthenticationFailed) as excinfo:
            token_auth.authenticate(request)
        assert "Token expired" in str(excinfo.value)

    def test_authentication_invalid_token(self, token_auth):
        request = APIRequestFactory().get("/", HTTP_AUTHORIZATION="Bearer invalid_token")
        with pytest.raises(exceptions.AuthenticationFailed) as excinfo:
            token_auth.authenticate(request)
        assert "Invalid token" in str(excinfo.value)

    def test_authentication_missing_auth_header(self, token_auth):
        request = APIRequestFactory().get("/")
        result = token_auth.authenticate(request)
        assert result is None
