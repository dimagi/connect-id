from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from django.utils.timezone import now
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error

from users.const import ErrorCodes
from users.factories import UserDeviceInfoFactory, UserFactory
from users.oauth import ConnectOAuth2Validator


def _oauth_request_mock():
    return MagicMock(uri="/token", http_method="POST", decoded_body=[], headers={})


@pytest.mark.django_db
class TestConnectOAuth2ValidatorUser:
    def setup_method(self):
        self.validator = ConnectOAuth2Validator()

    def test_successful_auth_updates_last_accessed(self):
        user = UserFactory()
        raw_password = "testpass"
        old_time = now() - timedelta(days=1)
        device = UserDeviceInfoFactory(user=user, raw_password=raw_password, last_accessed=old_time)

        result = self.validator.validate_user(
            user.username, raw_password, client=MagicMock(), request=_oauth_request_mock()
        )
        assert result is True
        device.refresh_from_db()
        assert device.last_accessed > old_time

    def test_failed_auth_different_device_raises_custom_error(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="old_pass",
            device="Old Phone",
            configured_at=now() - timedelta(days=60),
            last_accessed=now() - timedelta(days=5),
        )
        UserDeviceInfoFactory(
            user=user,
            raw_password="new_pass",
            device="New Phone",
            configured_at=now() - timedelta(days=10),
            last_accessed=now(),
        )

        with pytest.raises(CustomOAuth2Error) as exc_info:
            self.validator.validate_user(user.username, "old_pass", client=MagicMock(), request=_oauth_request_mock())
        assert exc_info.value.error == ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE

    def test_failed_auth_no_device_match(self):
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="some_pass")

        result = self.validator.validate_user(
            user.username, "totally_wrong", client=MagicMock(), request=_oauth_request_mock()
        )
        assert result is False

    def test_failed_auth_old_access_returns_false(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="old_pass",
            device="Old Phone",
            configured_at=now() - timedelta(days=120),
            last_accessed=now() - timedelta(days=60),
        )
        UserDeviceInfoFactory(
            user=user,
            raw_password="new_pass",
            device="New Phone",
            configured_at=now() - timedelta(days=45),
            last_accessed=now() - timedelta(days=35),
        )

        result = self.validator.validate_user(
            user.username, "old_pass", client=MagicMock(), request=_oauth_request_mock()
        )
        assert result is False
