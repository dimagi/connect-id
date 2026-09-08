import threading
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth.hashers import check_password
from django.db import IntegrityError, connection
from django.utils.timezone import now

from users.const import MAX_OTP_VERIFY_ATTEMPTS
from users.factories import (
    ConfigurationSessionFactory,
    PhoneDeviceFactory,
    SessionEmailOTPDeviceFactory,
    SessionPhoneDeviceFactory,
    UserDeviceInfoFactory,
    UserEmailOTPDeviceFactory,
    UserFactory,
)
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


# A token is always six digits, so this can never accidentally be the right one.
WRONG_TOKEN = "not-the-token"

DEVICE_FACTORIES = [
    PhoneDeviceFactory,
    SessionPhoneDeviceFactory,
    UserEmailOTPDeviceFactory,
    SessionEmailOTPDeviceFactory,
]


@pytest.fixture(params=DEVICE_FACTORIES, ids=lambda f: f._meta.model.__name__)
def otp_device(request, db):
    """One saved device of each concrete BaseOTPDevice subclass."""
    return request.param()


@pytest.fixture(autouse=True)
def mock_otp_delivery():
    """Stub out both delivery channels so generate_challenge() does no real sending."""
    with mock.patch("users.models.send_sms"), mock.patch("users.email_utils.send_email_otp_message"):
        yield


@pytest.mark.django_db
class TestOTPDeviceFailedVerifications:
    def test_counter_starts_at_zero(self, otp_device):
        assert otp_device.failed_verifications == 0
        assert otp_device.verify_attempts_left == MAX_OTP_VERIFY_ATTEMPTS
        assert not otp_device.is_exhausted

    def test_failed_verify_increments_counter(self, otp_device):
        otp_device.generate_challenge()

        for expected_failures in range(1, MAX_OTP_VERIFY_ATTEMPTS + 1):
            assert not otp_device.verify_token(WRONG_TOKEN)
            assert otp_device.failed_verifications == expected_failures
            assert otp_device.verify_attempts_left == MAX_OTP_VERIFY_ATTEMPTS - expected_failures

        assert otp_device.is_exhausted

    def test_exhaustion_burns_the_token(self, otp_device):
        otp_device.generate_challenge()
        correct_token = otp_device.token

        for _ in range(MAX_OTP_VERIFY_ATTEMPTS):
            assert not otp_device.verify_token(WRONG_TOKEN)

        otp_device.refresh_from_db()
        assert otp_device.token is None
        assert otp_device.valid_until <= now()

        # The correct code is now refused too — the token is gone, not merely rejected.
        assert not otp_device.verify_token(correct_token)

    def test_verifying_an_exhausted_device_does_not_climb_further(self, otp_device):
        otp_device.generate_challenge()
        for _ in range(MAX_OTP_VERIFY_ATTEMPTS + 2):
            assert not otp_device.verify_token(WRONG_TOKEN)

        assert otp_device.failed_verifications == MAX_OTP_VERIFY_ATTEMPTS
        assert otp_device.verify_attempts_left == 0

    def test_successful_verify_resets_counter(self, otp_device):
        otp_device.generate_challenge()
        correct_token = otp_device.token

        assert not otp_device.verify_token(WRONG_TOKEN)
        assert not otp_device.verify_token(WRONG_TOKEN)
        assert otp_device.failed_verifications == 2

        assert otp_device.verify_token(correct_token)
        assert otp_device.failed_verifications == 0

        otp_device.refresh_from_db()
        assert otp_device.failed_verifications == 0

    def test_natural_expiry_resets_counter_and_backoff(self, otp_device):
        otp_device.generate_challenge()
        assert otp_device.attempts == 1

        assert not otp_device.verify_token(WRONG_TOKEN)
        assert not otp_device.verify_token(WRONG_TOKEN)

        # Let the token lapse on its own rather than burning it.
        otp_device.valid_until = now() - timedelta(minutes=1)
        otp_device.save()
        otp_device.generate_challenge()

        assert otp_device.failed_verifications == 0
        # attempts was zeroed before this send, so the ladder is back at the bottom.
        assert otp_device.attempts == 1

    def test_burned_token_keeps_its_backoff(self, otp_device):
        otp_device.generate_challenge()
        assert otp_device.attempts == 1

        for _ in range(MAX_OTP_VERIFY_ATTEMPTS):
            assert not otp_device.verify_token(WRONG_TOKEN)

        otp_device.generate_challenge()

        # A fresh token, so guesses are allowed again...
        assert otp_device.failed_verifications == 0
        assert not otp_device.is_exhausted
        assert otp_device.token is not None
        # ...but attempts was not zeroed, so the resend interval keeps doubling. This is
        # what stops three wrong guesses from earning a free new code, over and over.
        assert otp_device.attempts == 2


@pytest.mark.django_db(transaction=True)
class TestOTPDeviceConcurrentVerification:
    def test_racing_wrong_guesses_each_count(self, otp_device):
        otp_device.generate_challenge()

        racers = 2
        start = threading.Barrier(racers)
        errors = []

        def attempt_verify():
            try:
                start.wait(timeout=10)
                otp_device.__class__.objects.get(pk=otp_device.pk).verify_token(WRONG_TOKEN)
            except Exception as e:  # surfaced below rather than lost in the thread
                errors.append(e)
            finally:
                connection.close()

        threads = [threading.Thread(target=attempt_verify) for _ in range(racers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)

        assert not errors, errors
        otp_device.refresh_from_db()
        # Both increments survived — the row lock stops a read-modify-write from losing one.
        assert otp_device.failed_verifications == racers
