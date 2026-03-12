import base64
from datetime import timedelta

import pytest
from django.test import RequestFactory
from django.utils.timezone import now
from rest_framework import exceptions
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from users.auth import DeviceBasicAuthentication
from users.const import ErrorCodes
from users.factories import UserDeviceInfoFactory, UserFactory
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


@pytest.mark.django_db
class TestDeviceBasicAuthentication:
    def setup_method(self):
        self.auth = DeviceBasicAuthentication()
        self.factory = RequestFactory()

    def _make_request(self, username, password):
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        return self.factory.get("/", HTTP_AUTHORIZATION=f"Basic {credentials}")

    def test_successful_auth_updates_last_accessed(self):
        user = UserFactory()
        raw_password = "testpass"
        old_time = now() - timedelta(days=1)
        device = UserDeviceInfoFactory(user=user, raw_password=raw_password, last_accessed=old_time)

        request = self._make_request(user.username, raw_password)
        result_user, _ = self.auth.authenticate(request)
        assert result_user == user
        device.refresh_from_db()
        assert device.last_accessed > old_time

    def test_failed_auth_different_device(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="old_pass",
            device="Old Phone",
            last_accessed=now() - timedelta(days=5),
        )
        UserDeviceInfoFactory(
            user=user,
            raw_password="new_pass",
            device="New Phone",
            last_accessed=now(),
        )

        request = self._make_request(user.username, "old_pass")
        with pytest.raises(AuthenticationFailed) as exc_info:
            self.auth.authenticate(request)
        assert ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE in str(exc_info.value.detail)

    def test_failed_auth_old_access_no_special_error(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="old_pass",
            device="Old Phone",
            last_accessed=now() - timedelta(days=60),
        )
        UserDeviceInfoFactory(
            user=user,
            raw_password="new_pass",
            device="New Phone",
            last_accessed=now() - timedelta(days=35),
        )

        request = self._make_request(user.username, "old_pass")
        with pytest.raises(AuthenticationFailed) as exc_info:
            self.auth.authenticate(request)
        assert ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE not in str(exc_info.value.detail)

    def test_failed_auth_unknown_password(self):
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="some_pass")

        request = self._make_request(user.username, "totally_wrong")
        with pytest.raises(AuthenticationFailed) as exc_info:
            self.auth.authenticate(request)
        assert ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE not in str(exc_info.value.detail)
