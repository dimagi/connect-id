import json
import uuid
from datetime import timedelta
from unittest import mock
from unittest.mock import PropertyMock, patch

import factory
import pytest
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from faker import Faker
from fcm_django.models import FCMDevice

from payments.models import PaymentProfile
from services.ai.ocs import OpenChatStudio
from test_utils.decorators import skip_app_integrity_check
from users.const import NO_RECOVERY_PHONE_ERROR, TEST_NUMBER_PREFIX, ErrorCodes
from users.factories import PhoneDeviceFactory, RecoveryStatusFactory, SessionPhoneDeviceFactory, UserFactory
from users.fcm_utils import create_update_device
from users.models import (
    ConfigurationSession,
    ConnectUser,
    Credential,
    PhoneDevice,
    RecoveryStatus,
    SessionPhoneDevice,
    UserCredential,
    UserKey,
)
from utils.app_integrity.const import ErrorCodes as AppIntegrityErrorCodes


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
    @patch.object(PhoneDevice, "generate_challenge")
    def test_otp_device_created(self, generate_challenge_mock, auth_device):
        assert not PhoneDevice.objects.all().exists()

        response = auth_device.post(
            reverse("validate_phone"),
        )

        assert response.status_code == 200
        assert PhoneDevice.objects.all().exists()
        generate_challenge_mock.assert_called_once()


class TestValidateSecondaryPhone:
    def test_no_recovery_phone(self, auth_device):
        endpoint = reverse("validate_secondary_phone")
        response = auth_device.post(
            endpoint,
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
    @patch.object(PhoneDevice, "generate_challenge")
    def test_missing_phone_number(self, generate_challenge_mock, client, user):
        response = client.post(
            reverse("recover_account"),
            data={},
        )

        assert response.status_code == 400
        assert response.json()["error"] == "OTP missing required key phone"

        generate_challenge_mock.assert_not_called()
        assert not RecoveryStatus.objects.filter(user=user).exists()

    @patch.object(PhoneDevice, "generate_challenge")
    def test_success(self, generate_challenge_mock, client, user):
        user.phone_number = TEST_NUMBER_PREFIX + "1234567"
        user.save()
        PhoneDeviceFactory(user=user, phone_number=user.phone_number)

        response = client.post(
            reverse("recover_account"),
            data={"phone": user.phone_number},
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
class TestAddCredential:
    endpoint = reverse("add_credential")

    def test_no_auth(self, client):
        response = client.post(self.endpoint)
        assert response.status_code == 403

    @patch("users.models.send_sms")
    def test_success(self, mock_add_credential, authed_client, user):
        app_id = uuid.uuid4().hex
        payload = {
            "credentials": [
                {
                    "users": [user.phone_number.raw_input, "1234567890"],
                    "title": "Test Credential",
                    "issuer": "HQ",
                    "app_id": app_id,
                    "type": "DELIVER",
                    "level": "ACTIVE_3_MONTHS",
                }
            ]
        }
        response = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response.status_code == 200
        assert UserCredential.objects.all().count() == 1
        cred = Credential.objects.all().first()
        assert cred.title == "Test Credential"
        assert cred.issuing_authority == "HQ"
        assert cred.level == "ACTIVE_3_MONTHS"
        assert cred.type == "DELIVER"
        assert cred.app_id == app_id

    @patch("users.models.send_sms")
    def test_bulk_add(self, mock_add_credential, authed_client):
        users = UserFactory.create_batch(2)
        payload = {
            "credentials": [
                {
                    "users": [users[0].phone_number.raw_input],
                    "title": "Test Credential",
                    "issuer": "HQ",
                    "app_id": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "ACTIVE_3_MONTHS",
                },
                {
                    "users": [users[1].phone_number.raw_input],
                    "title": "Test Credential 2",
                    "issuer": "CONNECT",
                    "opp_id": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "ACTIVE_3_MONTHS",
                },
            ]
        }
        response = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response.status_code == 200
        assert Credential.objects.all().count() == 2
        assert UserCredential.objects.all().count() == 2

    def test_missing_data(self, authed_client):
        payload = {
            "credentials": [
                {
                    "issuer": "HQ",
                    "level": "ACTIVE_3_MONTHS",
                }
            ]
        }
        response = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.INVALID_DATA}

    def test_no_phone_numbers(self, authed_client, user):
        payload = {
            "credentials": [
                {
                    "title": "Test Credential",
                    "issuer": "HQ",
                    "app_id": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "ACTIVE_3_MONTHS",
                }
            ]
        }
        response = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response.status_code == 200
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 0

    def test_invalid_phone_numbers(self, authed_client):
        payload = {
            "credentials": [
                {
                    "users": ["invalid-phone", "123", ""],
                    "title": "Test Credential",
                    "issuer": "HQ",
                    "app_id": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "ACTIVE_3_MONTHS",
                }
            ]
        }
        response = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response.status_code == 200
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 0

    @patch("users.models.send_sms")
    def test_duplicate_request(self, mock_add_credential, authed_client, user):
        payload = {
            "credentials": [
                {
                    "users": [user.phone_number.raw_input],
                    "title": "Test Credential",
                    "issuer": "HQ",
                    "app_id": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "ACTIVE_3_MONTHS",
                }
            ]
        }

        response1 = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response1.status_code == 200
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 1

        # Duplicate request should not create new credentials
        response2 = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response2.status_code == 200
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 1

    def test_malformed_json(self, authed_client):
        response = authed_client.post(
            self.endpoint, data='{"credentials": [{"invalid": json}]}', content_type="application/json"
        )
        assert response.status_code == 400

    def test_missing_credentials_key(self, authed_client):
        payload = {"invalid_key": []}
        response = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.MISSING_DATA}


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
    def test_success(self, mock_initiate_deactivation, client, recovery_status):
        response = client.post(
            self.endpoint,
            self.get_post_data(recovery_status.user, recovery_status),
        )
        assert response.status_code == 200
        assert isinstance(response, HttpResponse)
        mock_initiate_deactivation.assert_called()

    def test_invalid_user(self, client):
        response = client.post(
            self.endpoint,
            self.get_post_data(),
        )
        self.assert_fail_response(
            response,
            expected_code=ErrorCodes.USER_DOES_NOT_EXIST,
            expected_status=400,
        )

    def test_invalid_secret_key(self, client, recovery_status):
        response = client.post(
            self.endpoint,
            self.get_post_data(recovery_status.user),
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


@pytest.mark.django_db
class TestConfirmBackupCodeApi:
    url = reverse("confirm_backup_code")

    def test_phone_not_validated(self, authed_client_token, valid_token):
        valid_token.is_phone_validated = False
        valid_token.save()

        response = authed_client_token.post(self.url, data={})
        assert response.status_code == 403
        assert response.json() == {"error_code": ErrorCodes.PHONE_NOT_VALIDATED}

    def test_no_pin_set(self, authed_client_token):
        response = authed_client_token.post(self.url, data={"recovery_pin": "4321"})
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.NO_RECOVERY_PIN_SET}

    def test_wrong_pin(self, authed_client_token, user):
        user.set_recovery_pin("1234")
        user.save()

        response = authed_client_token.post(self.url, data={"recovery_pin": "4321"})
        assert response.status_code == 200

        user.refresh_from_db()
        assert user.failed_backup_code_attempts == 1
        assert response.json() == {"attempts_left": 2}

    def test_account_orphaned(self, authed_client_token, user):
        user.set_recovery_pin("4321")
        user.failed_backup_code_attempts = 2
        user.save()

        response = authed_client_token.post(self.url, data={"recovery_pin": "1234"})
        assert response.status_code == 200
        assert response.json() == {"error_code": ErrorCodes.LOCKED_ACCOUNT}

        user.refresh_from_db()
        assert not user.is_active
        assert user.is_locked

    def test_successful_code_check(self, authed_client_token, valid_token, user):
        user.set_recovery_pin("1234")
        user.failed_backup_code_attempts = 2
        user.save()

        response = authed_client_token.post(self.url, data={"recovery_pin": "1234"})
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.failed_backup_code_attempts == 0

        response_data = response.json()

        assert response_data["username"] == user.username
        assert user.check_password(response_data["password"])
        assert UserKey.objects.filter(key=response_data.get("db_key")).exists()


class TestChangePhone:
    def test_phone_is_validated(self, auth_device, user):
        user.phone_validated = True
        user.save()

        response = self._make_post(auth_device, data={})
        assert response.status_code == 400
        assert response.json()["error"] == "You cannot change a validated number"

    def test_old_number_mismatch(self, auth_device, user):
        response = self._make_post(auth_device, data={"old_phone_number": "1234"})
        assert response.status_code == 400
        assert response.json()["error"] == "Old phone number does not match"

    def test_invalid_new_phone_number(self, auth_device, user):
        data = {"old_phone_number": user.phone_number, "new_phone_number": "1234567890"}
        response = self._make_post(auth_device, data=data)
        assert response.status_code == 400

    def test_success(self, auth_device, user):
        data = {"old_phone_number": user.phone_number, "new_phone_number": factory.Faker("phone_number")}
        response = self._make_post(auth_device, data=data)
        assert response.status_code == 400

    def _make_post(self, client, data):
        return client.post(
            reverse("change_phone"),
            data=data,
        )


class TestChangePassword:
    def test_success(self, auth_device, user):
        response = self._make_post(auth_device, data={"password": "Ydi!asnf#i%48fnjas"})
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.check_password("Ydi!asnf#i%48fnjas")

    def test_no_password(self, auth_device):
        response = self._make_post(auth_device, data={"password": ""})
        assert response.status_code == 400

    def test_weak_password(self, auth_device):
        response = self._make_post(auth_device, data={"password": "1234"})
        assert response.status_code == 400

    def _make_post(self, client, data):
        return client.post(
            reverse("change_password"),
            data=data,
        )


class TestSetRecoveryPin:
    def test_success(self, auth_device, user):
        response = self._make_post(auth_device, data={"recovery_pin": "1234"})
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.check_recovery_pin("1234")

    def test_no_pin(self, auth_device, user):
        response = self._make_post(auth_device, data={"recovery_pin": ""})
        assert response.status_code == 400
        assert response.json()["error"] == ErrorCodes.MISSING_RECOVERY_PIN

    def _make_post(self, client, data):
        return client.post(
            reverse("set_recovery_pin"),
            data=data,
        )


class TestUpdatePaymentProfilePhone:
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
        )

        generate_challenge_mock.assert_called_once()
        profile = PaymentProfile.objects.get(user=user)

        assert profile.phone_number == user.phone_number
        assert profile.owner_name == user.name
        assert not profile.is_verified
        assert profile.status == PaymentProfile.PENDING


@pytest.mark.django_db
class TestUpdateProfile:
    test_number = "+27734567657"

    url = reverse("update_profile")

    def test_success(self, auth_device, user):
        data = {"name": "FooBar", "secondary_phone": "+27731234567"}
        user.phone_number = self.test_number
        user.save()
        response = auth_device.post(self.url, data)
        assert response.status_code == 200
        assert isinstance(response, HttpResponse)

        updated_user = ConnectUser.objects.get(id=user.id)
        assert updated_user.name == data["name"]
        assert updated_user.recovery_phone == data["secondary_phone"]

    @mock.patch("users.services.boto3.client")
    def test_update_photo(self, mock_boto3_client, auth_device, user):
        mock_s3 = mock.MagicMock()
        mock_boto3_client.return_value = mock_s3
        data = {"photo": "data:image/jpg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEB"}
        auth_device.post(self.url, data)
        mock_s3.put_object.assert_called_once()
        _, kwargs = mock_s3.put_object.call_args
        assert kwargs["Key"] == f"{user.username}.jpg"

    def test_update_photo_invalid(self, auth_device):
        data = {"photo": "data:image/png;base64,invalid-base64"}
        response = auth_device.post(self.url, data)
        assert response.status_code == 500
        assert isinstance(response, JsonResponse)
        assert response.json() == {"error": ErrorCodes.FAILED_TO_UPLOAD}

    @mock.patch("users.services.MAX_PHOTO_SIZE", 1)
    def test_update_photo_too_large(self, auth_device):
        data = {"photo": "data:image/jpg;base64, 123"}
        response = auth_device.post(self.url, data)
        assert response.status_code == 500
        assert isinstance(response, JsonResponse)
        assert response.json() == {"error": ErrorCodes.FILE_TOO_LARGE}

    def test_no_authentication(self, client):
        response = client.get(reverse("demo_users"))
        assert response.status_code == 403

    def test_validation_error(self, auth_device, user):
        data = {"secondary_phone": "-12415"}
        user.phone_number = self.test_number
        user.save()
        response = auth_device.post(self.url, data)
        assert response.status_code == 400
        assert isinstance(response, JsonResponse)
        assert response.json() == {"recovery_phone": ["The phone number entered is not valid."]}


class TestValidateFirebaseIDToken:
    url = reverse("validate_firebase_id_token")

    @property
    def post_data(self):
        return {"token": "123-456"}

    @mock.patch("users.views.auth.verify_id_token")
    def test_success(self, mock_verify_token, authed_client_token, valid_token):
        mock_verify_token.return_value = {"uid": "test-uid", "phone_number": valid_token.phone_number.as_e164}
        response = authed_client_token.post(self.url, data=self.post_data)
        assert response.status_code == 200
        assert isinstance(response, HttpResponse)
        mock_verify_token.assert_called_once_with(self.post_data["token"])

        config_session = ConfigurationSession.objects.get(key=valid_token.key)
        assert config_session.is_phone_validated is True

    def test_no_authentication(self, client, authed_client_token, expired_token):
        response = client.post(self.url)
        assert response.status_code == 401
        response = authed_client_token.post(
            self.url, data=self.post_data, HTTP_AUTHORIZATION=f"Bearer {expired_token.key}"
        )
        assert response.status_code == 401

    def test_missing_token(self, authed_client_token):
        response = authed_client_token.post(self.url)
        assert response.status_code == 400
        assert isinstance(response, JsonResponse)
        assert response.json() == {"error": ErrorCodes.MISSING_TOKEN}

    @mock.patch("users.views.auth.verify_id_token")
    def test_invalid_token(self, mock_verify_token, authed_client_token):
        mock_verify_token.return_value = {}
        response = authed_client_token.post(self.url, data=self.post_data)
        assert response.status_code == 400
        assert isinstance(response, JsonResponse)
        assert response.json() == {"error": ErrorCodes.INVALID_TOKEN}

    @mock.patch("users.views.auth.verify_id_token")
    def test_phone_mismatch(self, mock_verify_token, authed_client_token):
        mock_verify_token.return_value = {"uid": "test-uid", "phone_number": "+1234567890"}
        response = authed_client_token.post(self.url, data=self.post_data)
        assert response.status_code == 400
        assert isinstance(response, JsonResponse)
        assert response.json() == {"error": ErrorCodes.PHONE_MISMATCH}


@pytest.mark.django_db
class TestStartConfigurationView:
    @patch("utils.app_integrity.decorators.check_number_for_existing_invites")
    def test_no_integrity_token(self, check_number_mock, client):
        check_number_mock.return_value = False
        response = client.post(
            reverse("start_device_configuration"),
            data={},
        )
        assert response.status_code == 400
        assert response.json().get("error_code") == AppIntegrityErrorCodes.MISSING_DATA

    @skip_app_integrity_check
    def test_no_phone_number(self, client):
        response = client.post(
            reverse("start_device_configuration"),
            data={"gps_location": "0 0"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 400
        assert response.json().get("error_code") == ErrorCodes.MISSING_DATA

    @skip_app_integrity_check
    @patch("users.models.Nominatim.reverse")
    def test_no_gps_location(self, mock_nominatim_reverse, client):
        mock_location = mock.MagicMock()
        mock_location.raw = {"address": {"country_code": "XX"}}
        mock_nominatim_reverse.return_value = mock_location

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": Faker().phone_number()},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 200
        token = response.json().get("token")
        session = ConfigurationSession.objects.get(key=token)
        assert not session.gps_location

    @skip_app_integrity_check
    @patch("users.models.Nominatim.reverse")
    def test_gps_location_wrong_format(self, mock_nominatim_reverse, client):
        mock_location = mock.MagicMock()
        mock_location.raw = {"address": {"country_code": "XX"}}
        mock_nominatim_reverse.return_value = mock_location

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": Faker().phone_number(), "gps_location": "1.23.4"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 200

    @skip_app_integrity_check
    @patch("users.views.settings.BLACKLISTED_COUNTRY_CODES", ["XX"])
    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    def test_unsupported_country(self, mock_country_code, client):
        mock_country_code.return_value = "XX"
        phone_number = Faker().phone_number()
        gps_location = "1.2 3.4"

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": phone_number, "gps_location": gps_location},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 403
        assert response.json() == {"error_code": ErrorCodes.UNSUPPORTED_COUNTRY}

    @skip_app_integrity_check
    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    def test_session_started(self, mock_country_code, client):
        phone_number = Faker().phone_number()
        gps_location = "1.2 3.4"

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": phone_number, "gps_location": gps_location},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 200

        token = response.json().get("token")
        session = ConfigurationSession.objects.get(key=token)
        assert session.phone_number == phone_number
        assert session.gps_location == gps_location
        assert not session.is_phone_validated

    @skip_app_integrity_check
    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    def test_can_start_multiple_sessions(self, mock_country_code, client):
        phone_number = Faker().phone_number()

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": phone_number, "gps_location": "0 0"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 200
        token1 = response.json().get("token")
        session1 = ConfigurationSession.objects.get(key=token1)

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": phone_number, "gps_location": "0 0"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 200
        token2 = response.json().get("token")
        session2 = ConfigurationSession.objects.get(key=token2)

        assert session1.key != session2.key
        assert session1.phone_number == session2.phone_number

    @skip_app_integrity_check
    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    def test_is_demo_user(self, mock_country_code, client):
        phone_number = (TEST_NUMBER_PREFIX + "1234567",)
        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": phone_number, "gps_location": "0 0"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 200
        assert response.json().get("demo_user")

        token = response.json().get("token")
        session = ConfigurationSession.objects.get(key=token)
        assert session.is_phone_validated

    @skip_app_integrity_check
    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    def test_device_lock_required(self, mock_country_code, client):
        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": Faker().phone_number(), "gps_location": "0 0"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.json().get("required_lock") == ConnectUser.DeviceSecurity.BIOMETRIC

    @skip_app_integrity_check
    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    def test_biometric_lock_required(self, mock_country_code, client):
        pin_user = UserFactory()
        pin_user.device_security = ConnectUser.DeviceSecurity.PIN
        pin_user.save()

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": pin_user.phone_number, "gps_location": "0 0"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.json().get("required_lock") == ConnectUser.DeviceSecurity.PIN

    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    @patch("utils.app_integrity.decorators.check_number_for_existing_invites")
    @patch("utils.app_integrity.decorators.AppIntegrityService")
    def test_custom_application_id(self, integrity_service_mock, check_number_mock, mock_country_code, client):
        integrity_service_mock.verify_integrity.return_value = True
        check_number_mock.return_value = False
        client.post(
            reverse("start_device_configuration"),
            data={"application_id": "my.fancy.app"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        integrity_service_mock.assert_called_once_with(
            token="token", request_hash="hash", app_package="my.fancy.app", is_demo_user=False
        )

    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    @patch("utils.app_integrity.decorators.check_number_for_existing_invites")
    @patch("utils.app_integrity.decorators.AppIntegrityService")
    def test_demo_user(self, integrity_service_mock, check_number_mock, mock_country_code, client):
        integrity_service_mock.verify_integrity.return_value = True
        check_number_mock.return_value = False
        client.post(
            reverse("start_device_configuration"),
            data={
                "application_id": "my.fancy.app",
                "phone_number": TEST_NUMBER_PREFIX + "1234567",
                "gps_location": "0 0",
            },
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        integrity_service_mock.assert_called_once_with(
            token="token", request_hash="hash", app_package="my.fancy.app", is_demo_user=True
        )


@pytest.mark.django_db
class TestCheckUserSimilarity:
    urlname = "check_user_similarity"

    def test_no_name_provided(self, authed_client_token):
        response = authed_client_token.post(reverse(self.urlname))
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.NAME_REQUIRED}

    def test_phone_not_validated(self, authed_client_token, valid_token):
        valid_token.is_phone_validated = False
        valid_token.save()

        response = authed_client_token.post(reverse(self.urlname), data={"name": "NonExistentUser"})
        assert response.status_code == 403
        assert response.json() == {"error_code": ErrorCodes.PHONE_NOT_VALIDATED}

    def test_phone_number_does_not_exist(self, authed_client_token, valid_token):
        valid_token.is_phone_validated = True
        valid_token.phone_number = Faker().phone_number()
        valid_token.save()

        response = authed_client_token.post(reverse(self.urlname), data={"name": "NonExistentUser"})
        assert response.status_code == 200
        assert not response.json()["account_exists"]

    @patch.object(ConnectUser, "get_photo")
    @patch.object(OpenChatStudio, "check_name_similarity")
    def test_user_is_similar_user(self, check_similarity_mock, get_photo_mock, authed_client_token, user, valid_token):
        check_similarity_mock.return_value = True

        valid_token.phone_number = user.phone_number
        valid_token.is_phone_validated = True
        valid_token.save()

        user.name = "ExistingUser"
        user.save()
        get_photo_mock.return_value = "some_base64_photo_data"

        response = authed_client_token.post(reverse(self.urlname), data={"name": user.name})
        assert response.status_code == 200
        assert response.json()["account_exists"] is True
        assert response.json()["photo"] == "some_base64_photo_data"

    @patch.object(ConnectUser, "get_photo")
    @patch.object(OpenChatStudio, "check_name_similarity")
    def test_user_is_not_similar_user(
        self, check_similarity_mock, get_photo_mock, authed_client_token, user, valid_token
    ):
        check_similarity_mock.return_value = False

        valid_token.phone_number = user.phone_number
        valid_token.is_phone_validated = True
        valid_token.save()

        user.name = "ExistingUser"
        user.save()
        get_photo_mock.return_value = "some_base64_photo_data"

        response = authed_client_token.post(reverse(self.urlname), data={"name": "DifferentUser"})
        assert response.status_code == 200
        assert response.json()["account_exists"] is False
        assert response.json()["photo"] == ""


class TestCompleteProfileView:
    url = reverse("complete_profile")
    post_data = {
        "name": "Test User",
        "recovery_pin": "1234",
        "photo": "my-photo",
    }

    def test_no_authentication(self, client):
        response = client.post(self.url)
        assert response.status_code == 401

    @patch("users.views.upload_photo_to_s3")
    def test_success(self, mock_upload_photo, authed_client_token, valid_token):
        valid_token.phone_number = "+27729541234"
        valid_token.save()
        mock_upload_photo.return_value = None

        response = authed_client_token.post(self.url, data=self.post_data)
        assert response.status_code == 200

        user = ConnectUser.objects.get(phone_number=valid_token.phone_number)
        assert user.check_recovery_pin(self.post_data["recovery_pin"])

        user_key = UserKey.objects.get(user=user)
        response_json = response.json()
        assert response_json["username"] == user.username
        assert len(response_json["username"]) == 20
        assert user.check_password(response_json["password"])
        assert response_json["db_key"] == user_key.key

    def test_missing_required_fields(self, authed_client_token, valid_token):
        valid_token.is_phone_validated = True
        valid_token.save()

        response = authed_client_token.post(self.url, data={})
        assert response.status_code == 400
        assert response.json() == {"error": ErrorCodes.MISSING_DATA}

    @patch("users.views.upload_photo_to_s3")
    def test_upload_photo_error(self, mock_upload_photo, authed_client_token, valid_token):
        valid_token.is_phone_validated = True
        valid_token.save()
        mock_upload_photo.return_value = "test-error"

        response = authed_client_token.post(self.url, data=self.post_data)
        assert response.status_code == 500
        assert response.json() == {"error": "test-error"}

    def test_phone_not_validated(self, authed_client_token, valid_token):
        valid_token.is_phone_validated = False
        valid_token.save()
        response = authed_client_token.post(self.url, data=self.post_data)
        assert response.status_code == 403
        assert response.json() == {"error": ErrorCodes.PHONE_NOT_VALIDATED}

    @patch("users.views.upload_photo_to_s3")
    def test_existing_account_deactivation(self, mock_upload_photo, authed_client_token, valid_token, user):
        assert user.is_active

        valid_token.phone_number = user.phone_number
        valid_token.save()
        mock_upload_photo.return_value = None

        response = authed_client_token.post(self.url, data=self.post_data)
        assert response.status_code == 200

        user.refresh_from_db()
        assert not user.is_active

        new_user = ConnectUser.objects.get(phone_number=valid_token.phone_number, is_active=True)
        assert new_user.username != user.username
        assert new_user.name == self.post_data["name"]


@pytest.mark.django_db
class TestSendSessionOtp:
    url = "/users/send_session_otp"

    @patch("users.models.SessionPhoneDevice.generate_challenge")
    def test_success(self, mock_generate_challenge, authed_client_token, valid_token):
        SessionPhoneDeviceFactory(session=valid_token, phone_number=valid_token.phone_number)
        response = authed_client_token.post(self.url)
        assert response.status_code == 200
        mock_generate_challenge.assert_called_once()

    def test_session_phone_device_creation(self, authed_client_token, valid_token):
        SessionPhoneDevice.objects.filter(session=valid_token).delete()

        with patch("users.models.SessionPhoneDevice.generate_challenge") as mock_generate_challenge:
            response = authed_client_token.post(self.url)
            assert response.status_code == 200
            assert SessionPhoneDevice.objects.filter(session=valid_token).exists()
            mock_generate_challenge.assert_called_once()


@pytest.mark.django_db
class TestConfirmSessionOtp:
    url = "/users/confirm_session_otp"

    @patch("users.models.SessionPhoneDevice.verify_token")
    def test_invalid_token(self, mock_verify_token, authed_client_token, valid_token):
        mock_verify_token.return_value = False

        # Set initial state: phone not validated
        valid_token.is_phone_validated = False
        valid_token.save()

        SessionPhoneDeviceFactory(
            session=valid_token,
            phone_number=valid_token.phone_number,
        )

        response = authed_client_token.post(self.url, data={"otp": "wrong"})

        assert response.status_code == 401
        assert response.json()["error"] == ErrorCodes.INCORRECT_OTP
        mock_verify_token.assert_called_once_with("wrong")

        valid_token.refresh_from_db()
        assert not valid_token.is_phone_validated

    @patch("users.models.SessionPhoneDevice.verify_token")
    def test_success(self, mock_verify_token, authed_client_token, valid_token):
        mock_verify_token.return_value = True

        # Set initial state: phone not validated
        valid_token.is_phone_validated = False
        valid_token.save()

        SessionPhoneDeviceFactory(
            session=valid_token,
            phone_number=valid_token.phone_number,
        )

        response = authed_client_token.post(self.url, data={"otp": "123456"})

        assert response.status_code == 200
        mock_verify_token.assert_called_once_with("123456")

        valid_token.refresh_from_db()
        assert valid_token.is_phone_validated

    @patch("users.models.SessionPhoneDevice.verify_token")
    def test_missing_otp(self, mock_verify_token, authed_client_token, valid_token):
        # Set initial state: phone not validated
        valid_token.is_phone_validated = False
        valid_token.save()

        SessionPhoneDeviceFactory(
            session=valid_token,
            phone_number=valid_token.phone_number,
        )

        mock_verify_token.return_value = False

        response = authed_client_token.post(self.url, data={})

        assert response.status_code == 401
        assert response.json()["error"] == ErrorCodes.INCORRECT_OTP
        mock_verify_token.assert_called_once_with(None)

        valid_token.refresh_from_db()
        assert not valid_token.is_phone_validated
