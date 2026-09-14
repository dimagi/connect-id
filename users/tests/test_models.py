import threading
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth.hashers import check_password
from django.db import IntegrityError, connection
from django.utils.timezone import now

from users.const import MAX_OTP_BURN_COOLDOWN_HOURS, MAX_OTP_VERIFY_ATTEMPTS
from users.exceptions import RateLimitedError
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


def burn_token(device):
    """Spend every guess on the device's live token, burning it."""
    for _ in range(MAX_OTP_VERIFY_ATTEMPTS):
        assert not device.verify_token(WRONG_TOKEN)


def wind_back(device, elapsed):
    """Pretend the last code went out `elapsed` ago, so its cooldown has been served."""
    device.otp_last_sent = now() - elapsed
    device.save()


PHONE_DEVICE_FACTORIES = [PhoneDeviceFactory, SessionPhoneDeviceFactory]
EMAIL_DEVICE_FACTORIES = [UserEmailOTPDeviceFactory, SessionEmailOTPDeviceFactory]
DEVICE_FACTORIES = PHONE_DEVICE_FACTORIES + EMAIL_DEVICE_FACTORIES


@pytest.fixture(params=DEVICE_FACTORIES, ids=lambda f: f._meta.model.__name__)
def otp_device(request, db):
    """One saved device of each concrete BaseOTPDevice subclass."""
    return request.param()


@pytest.fixture(params=EMAIL_DEVICE_FACTORIES, ids=lambda f: f._meta.model.__name__)
def email_device(request, db):
    """One saved device of each email subclass — the channel that charges hours."""
    return request.param()


@pytest.fixture(params=PHONE_DEVICE_FACTORIES, ids=lambda f: f._meta.model.__name__)
def phone_device(request, db):
    """One saved device of each SMS subclass — a burn there stays on the minute ladder."""
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
        # Nothing was burned, so resends stay on the minute ladder.
        assert otp_device.burned_tokens == 0

    def test_burn_delays_the_next_email_by_an_hour(self, email_device):
        email_device.generate_challenge()
        assert email_device.attempts == 1

        burn_token(email_device)

        # A burn keeps otp_last_sent, so the wait applies before the next code instead of
        # the burn earning one straight away.
        with pytest.raises(RateLimitedError) as excinfo:
            email_device._attempt_send(valid_secs=1800)

        # Hours, not the minutes an ordinary resend would have cost.
        assert excinfo.value.retry_after_seconds == pytest.approx(3600, abs=5)

        # Nothing was committed, so the token is still burned and unusable.
        email_device.refresh_from_db()
        assert email_device.token is None
        assert email_device.is_exhausted
        assert email_device.burned_tokens == 1

    def test_email_burn_cooldown_doubles_in_hours(self, email_device):
        email_device.generate_challenge()

        for expected_hours in [1, 2, MAX_OTP_BURN_COOLDOWN_HOURS]:
            burn_token(email_device)

            with pytest.raises(RateLimitedError) as excinfo:
                email_device._attempt_send(valid_secs=1800)
            assert excinfo.value.retry_after_seconds == pytest.approx(expected_hours * 3600, abs=5)

            # Serve the cooldown and collect the replacement code.
            wind_back(email_device, timedelta(hours=expected_hours))
            email_device.generate_challenge()
            assert email_device.token is not None
            assert not email_device.is_exhausted

        # The third burn's wait outlives the 4-hour configuration session, so that
        # session can never see another code.
        assert email_device.burned_tokens == 3

    def test_phone_burn_stays_on_the_minute_ladder(self, phone_device):
        phone_device.generate_challenge()
        assert phone_device.attempts == 1

        burn_token(phone_device)

        # SMS was left as it was: a burn still only costs the 2**attempts minutes an
        # ordinary resend does. _attempt_send rather than generate_challenge because the
        # phone devices swallow this error.
        with pytest.raises(RateLimitedError) as excinfo:
            phone_device._attempt_send(valid_secs=1800)
        assert excinfo.value.retry_after_seconds == pytest.approx(2 * 60, abs=5)

        wind_back(phone_device, timedelta(minutes=2))
        phone_device.generate_challenge()

        # The burn was still counted, it just does not buy a longer wait here.
        assert phone_device.burned_tokens == 1
        assert phone_device.token is not None
        assert phone_device.attempts == 2

    def test_resend_without_burning_stays_on_the_minute_ladder(self, otp_device):
        otp_device.generate_challenge()
        assert otp_device.attempts == 1

        # Two wrong guesses is short of the limit, so nothing is burned.
        assert not otp_device.verify_token(WRONG_TOKEN)
        assert not otp_device.verify_token(WRONG_TOKEN)

        # A code that never arrived is still only a minutes-long wait away from a resend.
        with pytest.raises(RateLimitedError) as excinfo:
            otp_device._attempt_send(valid_secs=1800)
        assert excinfo.value.retry_after_seconds == pytest.approx(2 * 60, abs=5)

        wind_back(otp_device, timedelta(minutes=2))
        otp_device.generate_challenge()
        assert otp_device.burned_tokens == 0
        assert otp_device.attempts == 2

    def test_successful_verify_resets_the_burn_ladder(self, otp_device):
        """The counter is cleared on every channel, whatever cooldown it feeds."""
        otp_device.generate_challenge()
        burn_token(otp_device)
        assert otp_device.burned_tokens == 1

        wind_back(otp_device, timedelta(hours=1))
        otp_device.generate_challenge()
        assert otp_device.verify_token(otp_device.token)

        otp_device.refresh_from_db()
        assert otp_device.burned_tokens == 0


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
