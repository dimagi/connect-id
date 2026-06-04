import pytest
from django.contrib.auth.hashers import check_password
from django.db import IntegrityError

from users.factories import ConfigurationSessionFactory, UserDeviceInfoFactory, UserFactory
from users.models import SessionEmailOTPDevice, UserEmailOTPDevice


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
        assert device_info.last_accessed is not None
        assert device_info.date_created is not None


@pytest.mark.django_db
class TestUserEmailOTPDevice:
    def test_email_unique_per_user(self):
        user = UserFactory()
        UserEmailOTPDevice.objects.create(user=user, email="a@b.com")
        with pytest.raises(IntegrityError):
            UserEmailOTPDevice.objects.create(user=user, email="a@b.com")


@pytest.mark.django_db
class TestSessionEmailOTPDevice:
    def test_email_unique_per_session(self):
        session = ConfigurationSessionFactory()
        SessionEmailOTPDevice.objects.create(session=session, email="a@b.com")
        with pytest.raises(IntegrityError):
            SessionEmailOTPDevice.objects.create(session=session, email="a@b.com")


@pytest.mark.django_db
class TestConfigurationSessionVerifiedEmail:
    def test_verified_email_defaults_to_none(self):
        session = ConfigurationSessionFactory()
        assert session.verified_email is None

    def test_verified_email_can_be_set(self):
        session = ConfigurationSessionFactory()
        session.verified_email = "user@example.com"
        session.save()
        session.refresh_from_db()
        assert session.verified_email == "user@example.com"


@pytest.mark.django_db
class TestConnectUserEmailUniqueConstraint:
    @pytest.mark.parametrize(
        "email, is_active, should_raise",
        [
            ("shared@example.com", True, True),  # two active users, same email → error
            ("", True, False),  # two active users, blank email → ok
            ("shared@example.com", False, False),  # two inactive users, same email → ok
        ],
    )
    def test_email_uniqueness_constraint(self, email, is_active, should_raise):
        UserFactory(email=email, is_active=is_active)
        if should_raise:
            with pytest.raises(IntegrityError):
                UserFactory(email=email, is_active=is_active)
        else:
            UserFactory(email=email, is_active=is_active)  # must not raise
