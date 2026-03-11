import pytest
from django.contrib.auth.hashers import check_password

from users.factories import UserDeviceInfoFactory


@pytest.mark.django_db
class TestUserDeviceInfo:
    def test_set_password_hashes(self):
        device_info = UserDeviceInfoFactory(raw_password="mypassword")
        assert device_info.password != "mypassword"
        assert check_password("mypassword", device_info.password)

    def test_check_password(self):
        device_info = UserDeviceInfoFactory(raw_password="mypassword")
        assert device_info.check_password("mypassword")
        assert not device_info.check_password("wrongpassword")

    def test_fields(self):
        device_info = UserDeviceInfoFactory()
        assert device_info.user is not None
        assert device_info.device == "Google Pixel 7"
        assert device_info.configured_at is not None
        assert device_info.last_accessed is not None
        assert device_info.date_created is not None
