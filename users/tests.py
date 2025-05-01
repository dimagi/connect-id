import json
from datetime import timedelta
from unittest import mock
from unittest.mock import patch

import factory
import pytest
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from fcm_django.models import FCMDevice

from payments.models import PaymentProfile
from test_utils.decorators import pass_app_integrity_test
from users.const import NO_RECOVERY_PHONE_ERROR, TEST_NUMBER_PREFIX, ErrorCodes
from users.factories import CredentialFactory, PhoneDeviceFactory, RecoveryStatusFactory, UserFactory
from users.fcm_utils import create_update_device
from users.models import ConnectUser, PhoneDevice, RecoveryStatus
from utils.app_integrity.const import ErrorCodes as IntegrityErrorCodes
from utils.app_integrity.google_play_integrity import AppIntegrityService


@pytest.mark.django_db
class TestRegistration:
    def test_registration_v1(self, client):
        response = client.post(
            "/users/register",
            {
                "username": "testuser",
                "password": "testpass",
                "phone_number": "+27734567657",
            },
            HTTP_ACCEPT="application/json; version=1.0",
        )
        assert response.status_code == 200, response.content
        user = ConnectUser.objects.get(username="testuser")
        assert user.phone_number == "+27734567657"

    def test_registration_v2_without_integrity_data(self, client):
        response = client.post(
            "/users/register",
            {
                "username": "testuser",
                "password": "testpass",
                "phone_number": "+27734567657",
            },
            HTTP_ACCEPT="application/json; version=2.0",
        )
        assert response.status_code == 400
        assert response.json()["error_code"] == IntegrityErrorCodes.INTEGRITY_DATA_MISSING
        assert not ConnectUser.objects.filter(username="testuser").exists()

    @patch.object(AppIntegrityService, "verify_integrity", new=lambda x: ())
    def test_registration_v2_integrity_passed(self, client):
        response = client.post(
            "/users/register",
            {
                "username": "testuser",
                "password": "testpass",
                "phone_number": "+27734567657",
            },
            HTTP_ACCEPT="application/json; version=2.0",
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )
        assert response.status_code == 200, response.content
        user = ConnectUser.objects.get(username="testuser")
        assert user.phone_number == "+27734567657"


@pytest.mark.django_db
def test_registration_with_fcm_token(client):
    response = client.post(
        "/users/register",
        {"username": "testuser", "password": "testpass", "phone_number": "+27734567657", "fcm_token": "testtoken"},
        HTTP_ACCEPT="application/json; version=1.0",
    )
    assert response.status_code == 200, response.content
    user = ConnectUser.objects.get(username="testuser")
    device = FCMDevice.objects.get(user=user)
    assert device.registration_id == "testtoken"
    assert device.type == "android"
    assert device.active is True


def test_create_update_device__existing(user):
    response = create_update_device(user, "testtoken")
    assert response.status_code == 201, response.content

    update_response = create_update_device(user, "testtoken")
    assert update_response.status_code == 202, update_response.content
    assert FCMDevice.objects.filter(user=user).count() == 1


def test_create_update_device__reactivate(user):
    response = create_update_device(user, "testtoken")
    assert response.status_code == 201, response.content
    device = FCMDevice.objects.get(user=user)
    device.active = False
    device.save()

    update_response = create_update_device(user, "testtoken")
    assert update_response.status_code == 200, update_response.content
    device.refresh_from_db()
    assert device.active is True


def test_create_update_device__new_device(user):
    response = create_update_device(user, "testtoken")
    assert response.status_code == 201, response.content

    update_response = create_update_device(user, "testtoken1")
    assert update_response.status_code == 201, update_response.content
    assert FCMDevice.objects.filter(user=user).count() == 2
    active_device = FCMDevice.objects.get(user=user, active=True)
    assert active_device.registration_id == "testtoken1"


def test_create_update_device__update_old_device(user):
    test_create_update_device__new_device(user)

    # attempt to updated old device
    response = create_update_device(user, "testtoken")
    assert response.status_code == 202, response.content
    assert response.content == b'{"warning": "Another device is already active"}'


def test_otp_generation(user):
    with mock.patch("users.models.send_sms"):
        phone_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.phone_number, user=user)
        phone_device.generate_challenge()

        assert phone_device.token is not None
        assert phone_device.otp_last_sent is not None


def test_otp_generation_after_two_minutes(user):
    with mock.patch("users.models.send_sms") as send_sms:
        phone_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.phone_number, user=user)
        phone_device.generate_challenge()
        token = phone_device.token
        assert token is not None
        assert phone_device.otp_last_sent is not None
        assert send_sms.call_count == 1

        phone_device.generate_challenge()
        assert phone_device.token == token
        assert send_sms.call_count == 1

        phone_device.otp_last_sent -= timedelta(minutes=2)
        phone_device.save()
        phone_device.generate_challenge()
        assert phone_device.token == token
        assert send_sms.call_count == 2


def test_otp_generation_after_five_minutes(user):
    with mock.patch("users.models.send_sms") as send_sms:
        phone_device, _ = PhoneDevice.objects.get_or_create(phone_number=user.phone_number, user=user)
        phone_device.generate_challenge()
        token = phone_device.token
        assert phone_device.token is not None
        assert phone_device.otp_last_sent is not None
        assert send_sms.call_count == 1

        phone_device.otp_last_sent -= timedelta(minutes=3)
        phone_device.save()
        phone_device.generate_challenge()
        assert phone_device.token is not None
        assert phone_device.token == token
        assert send_sms.call_count == 2
        phone_device.valid_until -= timedelta(minutes=25)
        phone_device.save()
        phone_device.generate_challenge()
        assert phone_device.token is not None
        assert phone_device.token != token
        assert send_sms.call_count == 3


class TestValidatePhone:
    @pass_app_integrity_test
    @patch.object(PhoneDevice, "generate_challenge")
    def test_otp_device_created(self, generate_challenge_mock, auth_device):
        assert not PhoneDevice.objects.all().exists()

        response = auth_device.post(
            reverse("validate_phone"),
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )

        assert response.status_code == 200
        assert PhoneDevice.objects.all().exists()
        generate_challenge_mock.assert_called_once()


class TestValidateSecondaryPhone:
    @pass_app_integrity_test
    def test_no_recovery_phone(self, auth_device):
        endpoint = reverse("validate_secondary_phone")
        response = auth_device.post(
            endpoint,
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )
        assert isinstance(response, JsonResponse)
        assert response.status_code == 400
        assert response.json() == {"error": NO_RECOVERY_PHONE_ERROR}


class TestConfirmOTP:
    @patch.object(PhoneDevice, "verify_token")
    def test_invalid_token(self, verify_token_mock, auth_device, user):
        verify_token_mock.return_value = False

        user.phone_number = TEST_NUMBER_PREFIX + "1234567"
        user.save()
        PhoneDeviceFactory(user=user, phone_number=user.phone_number)

        response = auth_device.post(reverse("confirm_otp"), data={})

        assert response.status_code == 401
        assert response.json()["error"] == "OTP token is incorrect"
        user.refresh_from_db()
        assert not user.phone_validated

    @patch.object(PhoneDevice, "verify_token")
    def test_success(self, verify_token_mock, auth_device, user):
        verify_token_mock.return_value = True

        user.phone_number = TEST_NUMBER_PREFIX + "1234567"
        user.save()
        PhoneDeviceFactory(user=user, phone_number=user.phone_number)

        response = auth_device.post(reverse("confirm_otp"), data={"token": "112233"})

        assert response.status_code == 200
        user.refresh_from_db()
        assert user.phone_validated


class TestConfirmSecondaryOTP:
    def test_no_recovery_phone(self, auth_device, user):
        endpoint = reverse("confirm_secondary_otp")
        response = auth_device.post(endpoint)
        assert isinstance(response, JsonResponse)
        assert response.status_code == 400
        assert response.json() == {"error": NO_RECOVERY_PHONE_ERROR}


class TestRecoverAccount:
    @pass_app_integrity_test
    @patch.object(PhoneDevice, "generate_challenge")
    def test_missing_phone_number(self, generate_challenge_mock, client, user):
        response = client.post(
            reverse("recover_account"),
            data={},
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )

        assert response.status_code == 400
        assert response.json()["error"] == "OTP missing required key phone"

        generate_challenge_mock.assert_not_called()
        assert not RecoveryStatus.objects.filter(user=user).exists()

    @pass_app_integrity_test
    @patch.object(PhoneDevice, "generate_challenge")
    def test_success(self, generate_challenge_mock, client, user):
        user.phone_number = TEST_NUMBER_PREFIX + "1234567"
        user.save()
        PhoneDeviceFactory(user=user, phone_number=user.phone_number)

        response = client.post(
            reverse("recover_account"),
            data={"phone": user.phone_number},
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )

        assert response.status_code == 200
        assert response.json()["secret"]

        generate_challenge_mock.assert_called_once()

        status = RecoveryStatus.objects.get(user=user)
        assert status.step == RecoveryStatus.RecoverySteps.CONFIRM_PRIMARY
        assert status.secret_key == response.json()["secret"]


class TestConfirmRecoverOTP:
    secret_key = "chamber_of_secrets"

    @patch.object(PhoneDevice, "verify_token")
    def test_success(self, verify_token_mock, client, user):
        verify_token_mock.return_value = True
        self._prep_user(user)

        data = {
            "phone": user.phone_number,
            "secret_key": self.secret_key,
        }
        response = self._make_post(client, data=data)
        assert response.status_code == 200

        verify_token_mock.assert_called_once()

        status = RecoveryStatus.objects.get(user=user)
        assert status.step == RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY

    @patch.object(PhoneDevice, "verify_token")
    def test_missing_required_keys(self, verify_token_mock, client, user):
        verify_token_mock.return_value = True
        self._prep_user(user)

        data = {"phone": user.phone_number}
        response = self._make_post(client, data=data)
        assert response.status_code == 400
        assert response.json()["error"] == "OTP missing required key secret_key"

        verify_token_mock.assert_not_called()

        status = RecoveryStatus.objects.get(user=user)
        assert status.step == RecoveryStatus.RecoverySteps.CONFIRM_PRIMARY

    @patch.object(PhoneDevice, "verify_token")
    def test_secret_mismatch(self, verify_token_mock, client, user):
        verify_token_mock.return_value = True
        self._prep_user(user)

        data = {"phone": user.phone_number, "secret_key": "goblet_of_fire"}
        response = self._make_post(client, data=data)
        assert response.status_code == 401

        verify_token_mock.assert_not_called()

        status = RecoveryStatus.objects.get(user=user)
        assert status.step == RecoveryStatus.RecoverySteps.CONFIRM_PRIMARY

    @patch.object(PhoneDevice, "verify_token")
    def test_wrong_step_fails(self, verify_token_mock, client, user):
        verify_token_mock.return_value = True
        self._prep_user(user)

        status = RecoveryStatus.objects.get(user=user)
        status.step = RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY
        status.save()

        data = {"phone": user.phone_number, "secret_key": self.secret_key}
        response = self._make_post(client, data=data)
        assert response.status_code == 401

        verify_token_mock.assert_not_called()

    @patch.object(PhoneDevice, "verify_token")
    def test_incorrect_token(self, verify_token_mock, client, user):
        verify_token_mock.return_value = False
        self._prep_user(user)

        data = {"phone": user.phone_number, "secret_key": self.secret_key}
        response = self._make_post(client, data=data)
        assert response.status_code == 401
        assert response.json()["error"] == "OTP token is incorrect"

        verify_token_mock.assert_called_once()

    def _prep_user(self, user):
        user.phone_number = TEST_NUMBER_PREFIX + "1234567"
        user.save()
        PhoneDeviceFactory(user=user, phone_number=user.phone_number)

        RecoveryStatusFactory(
            user=user,
            secret_key=self.secret_key,
            step=RecoveryStatus.RecoverySteps.CONFIRM_PRIMARY,
        )

    def _make_post(self, client, data):
        return client.post(reverse("confirm_recovery_otp"), data=data)


@pytest.mark.django_db
class TestRecoverSecondaryPhone:
    def test_no_recovery_phone(self, client, user):
        RecoveryStatus.objects.create(
            user=user,
            secret_key="test_key",
            step=RecoveryStatus.RecoverySteps.CONFIRM_SECONDARY,
        )
        data = {
            "phone": user.phone_number,
            "secret_key": "test_key",
        }
        response = client.post(reverse("recover_secondary_phone"), data)
        assert isinstance(response, JsonResponse)
        assert response.status_code == 400
        assert json.loads(response.content) == {"error": NO_RECOVERY_PHONE_ERROR}


@pytest.mark.django_db
class TestFetchCredentials:
    def setup_method(self):
        self.url = "/users/fetch_credentials"
        CredentialFactory.create_batch(3, organization_slug="test_slug")
        CredentialFactory.create_batch(10)

    def assert_statements(self, response, expected_count):
        assert response.status_code == 200
        response_data = response.json()
        assert "credentials" in response_data
        assert len(response_data["credentials"]) == expected_count
        for credential in response_data["credentials"]:
            assert set(credential.keys()) == {"name", "slug"}

    def test_fetch_credential_with_org_slug(self, authed_client):
        response = authed_client.get(self.url + "?org_slug=test_slug")
        self.assert_statements(response, expected_count=3)

    def test_fetch_credential_without_org_slug(self, authed_client):
        response = authed_client.get(self.url)
        self.assert_statements(response, expected_count=13)


class BaseTestDeactivation:
    @property
    def endpoint(self):
        return reverse(self.urlname)

    def get_post_data(self, user=None, recovery_status=None):
        token = "123ABC"
        if user and user.deactivation_token:
            token = user.deactivation_token
        return {
            "phone_number": user.phone_number if user else "1234567890",
            "secret_key": recovery_status.secret_key if recovery_status else "123ABC",
            "token": token,
        }

    def assert_fail_response(self, response, expected_code, expected_status=401):
        assert response.status_code == expected_status
        assert isinstance(response, JsonResponse)
        assert json.loads(response.content) == {
            "error_code": expected_code,
        }


@pytest.mark.django_db
class TestInitiateDeactivation(BaseTestDeactivation):
    urlname = "initiate_deactivation"

    @mock.patch("users.models.ConnectUser.initiate_deactivation")
    @pass_app_integrity_test
    def test_success(self, mock_initiate_deactivation, client, recovery_status):
        response = client.post(
            self.endpoint,
            self.get_post_data(recovery_status.user, recovery_status),
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )
        assert response.status_code == 200
        assert isinstance(response, HttpResponse)
        mock_initiate_deactivation.assert_called()

    @pass_app_integrity_test
    def test_invalid_user(self, client):
        response = client.post(
            self.endpoint,
            self.get_post_data(),
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )
        self.assert_fail_response(
            response,
            expected_code=ErrorCodes.USER_DOES_NOT_EXIST,
            expected_status=400,
        )

    @pass_app_integrity_test
    def test_invalid_secret_key(self, client, recovery_status):
        response = client.post(
            self.endpoint,
            self.get_post_data(recovery_status.user),
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )
        self.assert_fail_response(
            response,
            expected_code=ErrorCodes.INVALID_SECRET_KEY,
        )


@pytest.mark.django_db
class TestConfirmDeactivation(BaseTestDeactivation):
    urlname = "confirm_deactivation"

    def test_success(self, client, recovery_status):
        response = client.post(self.endpoint, self.get_post_data(recovery_status.user, recovery_status))
        assert response.status_code == 200
        assert isinstance(response, HttpResponse)

        user = ConnectUser.objects.get(phone_number=recovery_status.user.phone_number)
        assert user.is_active is False

    def test_invalid_user(self, client):
        response = client.post(self.endpoint, self.get_post_data())
        self.assert_fail_response(
            response,
            expected_code=ErrorCodes.USER_DOES_NOT_EXIST,
            expected_status=400,
        )

    def test_invalid_secret_key(self, client, recovery_status):
        response = client.post(self.endpoint, self.get_post_data(recovery_status.user))
        self.assert_fail_response(
            response,
            expected_code=ErrorCodes.INVALID_SECRET_KEY,
        )

    def test_invalid_deactivation_token(self, client, recovery_status):
        data = self.get_post_data(recovery_status.user, recovery_status)
        data["token"] = "wrong"
        response = client.post(self.endpoint, data)
        self.assert_fail_response(
            response,
            expected_code=ErrorCodes.INVALID_TOKEN,
        )

    def test_expired_deactivation_token(self, client, recovery_status_with_expired_token_user):
        response = client.post(
            self.endpoint,
            self.get_post_data(recovery_status_with_expired_token_user.user, recovery_status_with_expired_token_user),
        )
        self.assert_fail_response(
            response,
            expected_code=ErrorCodes.TOKEN_EXPIRED,
        )


@pytest.mark.django_db
class TestGetDemoUsers:
    def setup_method(self):
        self.valid_user = UserFactory.create(
            phone_number=TEST_NUMBER_PREFIX + "1234567",
        )
        invalid_user = UserFactory.create(
            phone_number=TEST_NUMBER_PREFIX + "7654321",
            deactivation_token=None,
        )
        self.valid_device = PhoneDeviceFactory.create(
            phone_number=TEST_NUMBER_PREFIX + "1234567",
            user=self.valid_user,
        )
        PhoneDeviceFactory.create(phone_number=TEST_NUMBER_PREFIX + "7654321", token=None, user=invalid_user)

    @property
    def endpoint(self):
        return reverse("demo_users")

    def test_no_authentication(self, client):
        response = client.get(reverse("demo_users"))
        assert response.status_code == 403

    def test_success(self, authed_client):
        response = authed_client.get(self.endpoint)
        assert response.status_code == 200
        assert isinstance(response, JsonResponse)
        assert response.json() == {
            "demo_users": [
                {
                    "phone_number": TEST_NUMBER_PREFIX + "1234567",
                    "token": self.valid_device.token,
                },
                {
                    "phone_number": TEST_NUMBER_PREFIX + "1234567",
                    "token": self.valid_user.deactivation_token,
                },
            ]
        }


@pytest.mark.django_db
class TestRecoveryPinConfirmationApi:
    url = reverse("confirm_recovery_pin")

    def _get_post_data(self, recovery_status):
        return {
            "phone": recovery_status.user.phone_number,
            "secret_key": recovery_status.secret_key,
            "recovery_pin": "1234",
        }

    def test_recovery_status_secret_mismatch(self, recovery_status, client):
        data = self._get_post_data(recovery_status)
        data["secret_key"] = "another_test_key"
        response = client.post(self.url, data=data)
        assert response.status_code == 401

    def test_recovery_status_wrong_step(self, recovery_status, client):
        recovery_status.step = RecoveryStatus.RecoverySteps.RESET_PASSWORD
        recovery_status.save()

        response = client.post(self.url, data=self._get_post_data(recovery_status))
        assert response.status_code == 401

    def test_recovery_pin_not_set(self, recovery_status, client):
        data = self._get_post_data(recovery_status)

        recovery_status.user.recovery_pin = None
        recovery_status.user.save()

        response = client.post(self.url, data=data)
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.NO_RECOVERY_PIN_SET}

    def test_confirm_recovery_pin_success(self, recovery_status, client):
        recovery_status.user.set_recovery_pin("1234")
        recovery_status.user.save()

        response = client.post(self.url, data=self._get_post_data(recovery_status))

        recovery_status.refresh_from_db()
        assert response.status_code == 200
        assert recovery_status.step == RecoveryStatus.RecoverySteps.RESET_PASSWORD


class TestChangePhone:
    @pass_app_integrity_test
    def test_phone_is_validated(self, auth_device, user):
        user.phone_validated = True
        user.save()

        response = self._make_post(auth_device, data={})
        assert response.status_code == 400
        assert response.json()["error"] == "You cannot change a validated number"

    @pass_app_integrity_test
    def test_old_number_mismatch(self, auth_device, user):
        response = self._make_post(auth_device, data={"old_phone_number": "1234"})
        assert response.status_code == 400
        assert response.json()["error"] == "Old phone number does not match"

    @pass_app_integrity_test
    def test_invalid_new_phone_number(self, auth_device, user):
        data = {"old_phone_number": user.phone_number, "new_phone_number": "1234567890"}
        response = self._make_post(auth_device, data=data)
        assert response.status_code == 400

    @pass_app_integrity_test
    def test_success(self, auth_device, user):
        data = {"old_phone_number": user.phone_number, "new_phone_number": factory.Faker("phone_number")}
        response = self._make_post(auth_device, data=data)
        assert response.status_code == 400

    def _make_post(self, client, data):
        return client.post(
            reverse("change_phone"),
            data=data,
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )


class TestChangePassword:
    @pass_app_integrity_test
    def test_success(self, auth_device, user):
        response = self._make_post(auth_device, data={"password": "Ydi!asnf#i%48fnjas"})
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.check_password("Ydi!asnf#i%48fnjas")

    @pass_app_integrity_test
    def test_no_password(self, auth_device):
        response = self._make_post(auth_device, data={"password": ""})
        assert response.status_code == 400

    @pass_app_integrity_test
    def test_weak_password(self, auth_device):
        response = self._make_post(auth_device, data={"password": "1234"})
        assert response.status_code == 400

    def _make_post(self, client, data):
        return client.post(
            reverse("change_password"),
            data=data,
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )


class TestSetRecoveryPin:
    @pass_app_integrity_test
    def test_success(self, auth_device, user):
        response = self._make_post(auth_device, data={"recovery_pin": "1234"})
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.check_recovery_pin("1234")

    @pass_app_integrity_test
    def test_no_pin(self, auth_device, user):
        response = self._make_post(auth_device, data={"recovery_pin": ""})
        assert response.status_code == 400
        assert response.json()["error"] == "Missing recovery pin"

    def _make_post(self, client, data):
        return client.post(
            reverse("set_recovery_pin"),
            data=data,
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )


class TestUpdatePaymentProfilePhone:
    @pass_app_integrity_test
    @patch.object(PhoneDevice, "generate_challenge")
    @patch("payments.views.lookup_telecom_provider")
    def test_success(self, lookup_telecom_provider_mock, generate_challenge_mock, auth_device, user):
        lookup_telecom_provider_mock.return_value = "Test carrier"

        auth_device.post(
            reverse("update_payment_profile_phone"),
            data={
                "phone_number": user.phone_number,
                "owner_name": user.name,
            },
            HTTP_CC_INTEGRITY_TOKEN="integrity_token",
            HTTP_CC_REQUEST_HASH="request_hash",
        )

        generate_challenge_mock.assert_called_once()
        profile = PaymentProfile.objects.get(user=user)

        assert profile.phone_number == user.phone_number
        assert profile.owner_name == user.name
        assert not profile.is_verified
        assert profile.status == PaymentProfile.PENDING
