from datetime import timedelta

import pytest
from django.utils.timezone import now

from users.device_utils import check_login_from_different_device, find_device_for_password, update_device_last_accessed
from users.factories import UserDeviceInfoFactory, UserFactory


@pytest.mark.django_db
class TestFindDeviceForPassword:
    def test_finds_matching_device(self):
        user = UserFactory()
        device = UserDeviceInfoFactory(user=user, raw_password="password1")
        result = find_device_for_password(user, "password1")
        assert result == device

    def test_returns_none_for_wrong_password(self):
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="password1")
        result = find_device_for_password(user, "wrongpassword")
        assert result is None

    def test_finds_correct_device_among_multiple(self):
        user = UserFactory()
        device1 = UserDeviceInfoFactory(
            user=user,
            raw_password="password1",
            device="Old Phone",
            last_accessed=now() - timedelta(days=10),
        )
        device2 = UserDeviceInfoFactory(
            user=user,
            raw_password="password2",
            device="New Phone",
            last_accessed=now(),
        )
        assert find_device_for_password(user, "password1") == device1
        assert find_device_for_password(user, "password2") == device2

    def test_no_devices(self):
        user = UserFactory()
        assert find_device_for_password(user, "password1") is None


@pytest.mark.django_db
class TestUpdateDeviceLastAccessed:
    def test_updates_last_accessed(self):
        user = UserFactory()
        old_time = now() - timedelta(days=1)
        device = UserDeviceInfoFactory(user=user, raw_password="password1", last_accessed=old_time)
        update_device_last_accessed(user, "password1")
        device.refresh_from_db()
        assert device.last_accessed > old_time

    def test_no_matching_device(self):
        user = UserFactory()
        # Should not raise
        update_device_last_accessed(user, "wrongpassword")


@pytest.mark.django_db
class TestCheckLoginFromDifferentDevice:
    def test_old_device_password_recent_access(self):
        """User tries old device password, new device last accessed < 30 days ago."""
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="old_pass",
            device="Old Phone",
            last_accessed=now() - timedelta(days=5),
            configured_at=now() - timedelta(days=60),
        )
        UserDeviceInfoFactory(
            user=user,
            raw_password="new_pass",
            device="New Phone",
            last_accessed=now(),
            configured_at=now() - timedelta(days=10),
        )
        assert check_login_from_different_device(user, "old_pass") is True

    def test_old_device_password_old_access(self):
        """User tries old device password, but new device last accessed > 30 days ago."""
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="old_pass",
            device="Old Phone",
            last_accessed=now() - timedelta(days=60),
            configured_at=now() - timedelta(days=120),
        )
        UserDeviceInfoFactory(
            user=user,
            raw_password="new_pass",
            device="New Phone",
            last_accessed=now() - timedelta(days=35),
            configured_at=now() - timedelta(days=45),
        )
        assert check_login_from_different_device(user, "old_pass") is False

    def test_current_device_password(self):
        """User tries the latest device's password — not a different device."""
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="current_pass",
            device="Current Phone",
            last_accessed=now(),
            configured_at=now() - timedelta(days=5),
        )
        assert check_login_from_different_device(user, "current_pass") is False

    def test_no_matching_password(self):
        """Password doesn't match any device."""
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="some_pass")
        assert check_login_from_different_device(user, "unknown_pass") is False

    def test_no_devices(self):
        user = UserFactory()
        assert check_login_from_different_device(user, "any_pass") is False
