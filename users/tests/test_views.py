import json
import uuid
from datetime import datetime, timedelta
from unittest import mock
from unittest.mock import PropertyMock, patch

import factory
import pytest
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from faker import Faker
from fcm_django.models import FCMDevice

from messaging.factories import ChannelFactory, MessageFactory
from messaging.models import MessageDirection
from payments.models import PaymentProfile
from services.ai.ocs import OpenChatStudio
from test_utils.decorators import skip_app_integrity_check
from users.const import NO_RECOVERY_PHONE_ERROR, TEST_NUMBER_PREFIX, ErrorCodes, SMSMethods
from users.factories import (
    ConfigurationSessionFactory,
    CredentialFactory,
    PhoneDeviceFactory,
    RecoveryStatusFactory,
    SessionPhoneDeviceFactory,
    UserCredentialFactory,
    UserFactory,
)
from users.fcm_utils import create_update_device
from users.models import (
    ConfigurationSession,
    ConnectUser,
    Credential,
    DeviceIntegritySample,
    PhoneDevice,
    RecoveryStatus,
    SessionPhoneDevice,
    UserCredential,
    UserKey,
)
from utils.app_integrity.const import ErrorCodes as AppIntegrityErrorCodes
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


def test_create_update_device__different_user(user):
    test_token = "testtoken"
    create_update_device(user, test_token)

    another_user = UserFactory()
    response = create_update_device(another_user, test_token)

    assert response.status_code == 200
    assert FCMDevice.objects.filter(user=another_user, active=True).count() == 1
    assert FCMDevice.objects.filter(user=user, active=True).exists() is False


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
        assert response.status_code == 401

    def test_invalid_auth(self, authed_client, user):
        payload = {"credentials": [{"foo": "bar"}]}
        response = authed_client.post(self.endpoint, data=json.dumps(payload), content_type="application/json")
        assert response.status_code == 401
        assert response.json() == {"error_code": ErrorCodes.INVALID_CREDENTIALS}

    @patch("users.models.send_sms")
    def test_success(self, mock_add_credential, credential_issuing_client, credential_issuing_authority, user):
        app_id = uuid.uuid4().hex
        payload = {
            "credentials": [
                {
                    "usernames": [user.username, "does-not-exist"],
                    "title": "Test Credential",
                    "app_id": app_id,
                    "type": "DELIVER",
                    "level": "3MON_ACTIVE",
                    "slug": app_id,
                }
            ]
        }
        response = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response.status_code == 200
        assert response.json() == {"success": [0], "failed": []}
        assert UserCredential.objects.all().count() == 1
        cred = Credential.objects.all().first()
        assert cred.title == "Test Credential"
        assert cred.issuer == credential_issuing_authority
        assert cred.level == "3MON_ACTIVE"
        assert cred.type == "DELIVER"
        assert cred.app_id == app_id

    @patch("users.models.send_sms")
    def test_bulk_add(self, mock_add_credential, credential_issuing_client):
        users = UserFactory.create_batch(2)
        app_id = uuid.uuid4().hex
        payload = {
            "credentials": [
                {
                    "usernames": [users[0].username],
                    "title": "Test Credential",
                    "app_id": app_id,
                    "type": "DELIVER",
                    "level": "3MON_ACTIVE",
                    "slug": app_id,
                },
                {
                    "usernames": [users[1].username],
                    "title": "Test Credential 2",
                    "app_id": app_id,
                    "opp_id": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "6MON_ACTIVE",
                    "slug": app_id,
                },
            ]
        }
        response = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response.status_code == 200
        assert Credential.objects.all().count() == 2
        assert UserCredential.objects.all().count() == 2

    @patch("users.models.send_sms")
    def test_partial_fail(self, mock_add_credential, credential_issuing_client, user):
        app_id = uuid.uuid4().hex
        payload = {
            "credentials": [
                {
                    "usernames": [user.username],
                    "title": "Test Credential",
                    "app_id": app_id,
                    "type": "DELIVER",
                    "level": "3MON_ACTIVE",
                    "slug": app_id,
                },
                {
                    "title": "Test Credential 2",
                },
                {
                    "level": "6MON_ACTIVE",
                },
            ]
        }
        response = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response.status_code == 200
        assert response.json() == {"success": [0], "failed": [1, 2]}
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 1

    def test_missing_data(self, credential_issuing_client):
        payload = {
            "credentials": [
                {
                    "level": "3MON_ACTIVE",
                }
            ]
        }
        response = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response.status_code == 200
        assert response.json() == {"success": [], "failed": [0]}

    def test_no_usernames(self, credential_issuing_client):
        payload = {
            "credentials": [
                {
                    "title": "Test Credential",
                    "app_id": uuid.uuid4().hex,
                    "slug": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "3MON_ACTIVE",
                }
            ]
        }
        response = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response.status_code == 200
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 0

    def test_invalid_usernames(self, credential_issuing_client):
        payload = {
            "credentials": [
                {
                    "usernames": ["invalid-user", "123", ""],
                    "title": "Test Credential",
                    "app_id": uuid.uuid4().hex,
                    "slug": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "3MON_ACTIVE",
                }
            ]
        }
        response = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response.status_code == 200
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 0

    @patch("users.models.send_sms")
    def test_duplicate_request(self, mock_add_credential, credential_issuing_client, user):
        payload = {
            "credentials": [
                {
                    "usernames": [user.username],
                    "title": "Test Credential",
                    "app_id": uuid.uuid4().hex,
                    "slug": uuid.uuid4().hex,
                    "type": "DELIVER",
                    "level": "3MON_ACTIVE",
                }
            ]
        }

        response1 = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response1.status_code == 200
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 1

        # Duplicate request should not create new credentials
        response2 = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response2.status_code == 200
        assert Credential.objects.all().count() == 1
        assert UserCredential.objects.all().count() == 1

    def test_malformed_json(self, credential_issuing_client):
        response = credential_issuing_client.post(
            self.endpoint, data='{"credentials": [{"invalid": json}]}', content_type="application/json"
        )
        assert response.status_code == 400

    def test_missing_credentials_key(self, credential_issuing_client):
        payload = {"invalid_key": []}
        response = credential_issuing_client.post(
            self.endpoint, data=json.dumps(payload), content_type="application/json"
        )
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.MISSING_DATA}


@pytest.mark.django_db
class TestListCredentials:
    url = reverse("list_credentials")

    def test_success(self, auth_device, oauth_app, user, credential_issuing_authority):
        cred = CredentialFactory.create(
            title="Test Credential",
            type=Credential.CredentialTypes.DELIVER,
            level="ACTIVE_3_MONTH",
            issuer=credential_issuing_authority,
            app_id=uuid.uuid4().hex,
        )
        UserCredentialFactory.create(credential=cred, user=user)

        response = auth_device.get(self.url)
        assert response.status_code == 200
        assert response.json() == {
            "credentials": [
                {
                    "uuid": str(cred.uuid),
                    "app_id": cred.app_id,
                    "opp_id": None,
                    "date": cred.created_at.isoformat(),
                    "title": "Test Credential",
                    "issuer": "HQ",
                    "issuer_environment": "production",
                    "level": "ACTIVE_3_MONTH",
                    "type": "DELIVER",
                    "slug": cred.slug,
                }
            ]
        }

    def test_no_credentials(self, auth_device):
        response = auth_device.get(self.url)
        assert response.status_code == 200
        assert response.json() == {"credentials": []}

    def test_multiple_credentials(self, auth_device, user, credential_issuing_authority):
        cred_1 = CredentialFactory.create(title="Credential 1", issuer=credential_issuing_authority)
        cred_2 = CredentialFactory.create(title="Credential 2", issuer=credential_issuing_authority)
        cred_3 = CredentialFactory.create(title="Credential 3", issuer=credential_issuing_authority)
        UserCredentialFactory.create(credential=cred_3)
        UserCredential.objects.create(user=user, credential=cred_1)
        UserCredential.objects.create(user=user, credential=cred_2)

        response = auth_device.get(self.url)
        data = response.json()
        assert response.status_code == 200
        assert len(data["credentials"]) == 2

        titles = [cred["title"] for cred in data["credentials"]]
        assert "Credential 1" in titles
        assert "Credential 2" in titles

    def test_no_auth(self, api_client):
        response = api_client.get(self.url)
        assert response.status_code == 401

    def test_inactive_connect_user(self, auth_device, user):
        user.is_active = False
        user.save()
        response = auth_device.get(self.url)
        assert response.status_code == 401


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
        assert "invited_user" in response_data


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
            data={"phone_number": phone_number, "gps_location": gps_location, "cc_device_id": "device_id"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )
        assert response.status_code == 200

        token = response.json().get("token")
        session = ConfigurationSession.objects.get(key=token)
        assert session.phone_number == phone_number
        assert session.gps_location == gps_location
        assert not session.is_phone_validated
        assert session.device_id == "device_id"

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

    @skip_app_integrity_check
    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    @patch("utils.app_integrity.decorators.check_number_for_existing_invites")
    def test_invited_user_starts_session_on_api_v1(self, check_number_mock, mock_country_code, client):
        phone_number = Faker().phone_number()
        gps_location = "1.2 3.4"
        check_number_mock.return_value = True

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": phone_number, "gps_location": gps_location, "cc_device_id": "device_id"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
            HTTP_ACCEPT="application/json; version=1.0",
        )
        assert response.status_code == 200

        sms_method = response.json().get("sms_method")
        assert sms_method == SMSMethods.PERSONAL_ID
        assert "otp_fallback" not in response.json()

    @skip_app_integrity_check
    @patch("users.models.ConfigurationSession.country_code", new_callable=PropertyMock)
    @patch("utils.app_integrity.decorators.check_number_for_existing_invites")
    def test_invited_user_starts_session_on_api_v2(self, check_number_mock, mock_country_code, client):
        phone_number = Faker().phone_number()
        gps_location = "1.2 3.4"
        check_number_mock.return_value = True

        response = client.post(
            reverse("start_device_configuration"),
            data={"phone_number": phone_number, "gps_location": gps_location, "cc_device_id": "device_id"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
            HTTP_ACCEPT="application/json; version=2.0",
        )
        assert response.status_code == 200

        sms_method = response.json().get("sms_method")
        assert sms_method == SMSMethods.FIREBASE
        assert response.json().get("otp_fallback")


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
        valid_token.invited_user = False
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
        assert "invited_user" in response_json

    def test_missing_required_fields(self, authed_client_token, valid_token):
        valid_token.is_phone_validated = True
        valid_token.save()

        response = authed_client_token.post(self.url, data={})
        assert response.status_code == 400
        assert response.json() == {"error": ErrorCodes.MISSING_DATA}

    @patch("users.views.upload_photo_to_s3")
    def test_upload_photo_error(self, mock_upload_photo, authed_client_token, valid_token):
        valid_token.phone_number = "+919999999999"
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
    def test_existing_account(self, mock_upload_photo, authed_client_token, valid_token, user):
        assert user.is_active

        valid_token.phone_number = user.phone_number
        valid_token.save()
        mock_upload_photo.return_value = None

        response = authed_client_token.post(self.url, data=self.post_data)
        assert response.status_code == 401

        user.refresh_from_db()
        assert user.is_active

        new_user = ConnectUser.objects.get(phone_number=valid_token.phone_number, is_active=True)
        assert new_user.username == user.username
        assert new_user.name != self.post_data["name"]


@pytest.mark.django_db
class TestSendSessionOtp:
    url = "/users/send_session_otp"

    def test_not_invited_user(self, authed_client_token, valid_token):
        valid_token.invited_user = False
        valid_token.save()

        response = authed_client_token.post(self.url)
        assert response.status_code == 403
        assert response.json() == {"error_code": ErrorCodes.NOT_ALLOWED}

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

    def test_not_invited_user(self, authed_client_token, valid_token):
        valid_token.invited_user = False
        valid_token.save()

        response = authed_client_token.post(self.url)
        assert response.status_code == 403
        assert response.json() == {"error_code": ErrorCodes.NOT_ALLOWED}

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
            has_manual_otp=True,
        )

        response = authed_client_token.post(self.url, data={"otp": "123456"})

        assert response.status_code == 200
        mock_verify_token.assert_called_once_with("123456")

        valid_token.refresh_from_db()
        assert valid_token.is_phone_validated
        assert SessionPhoneDevice.objects.get(session=valid_token).has_manual_otp is True

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


@pytest.mark.django_db
class TestReportIntegrityView:
    url = reverse("report_integrity")

    def _load_verdict_from_file(self, response_filepath):
        with open(response_filepath) as file_data:
            verdict_response = json.load(file_data)
        return verdict_response

    def test_missing_device_id(self, client):
        response = client.post(
            self.url,
            data={"application_id": "com.example.app"},
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="test_hash",
        )
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.MISSING_DATA}

    def test_missing_request_id(self, client):
        response = client.post(
            self.url,
            data={"cc_device_id": "test_device_id"},
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="test_hash",
        )
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.MISSING_DATA}

    def test_missing_integrity_token(self, client):
        response = client.post(
            self.url,
            data={"cc_device_id": "test_device_id", "request_id": "test_uuid"},
            HTTP_CC_REQUEST_HASH="test_hash",
        )
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.MISSING_DATA}

    def test_missing_request_hash(self, client):
        response = client.post(
            self.url,
            data={"cc_device_id": "test_device_id", "request_id": "test_uuid"},
            HTTP_CC_INTEGRITY_TOKEN="test_token",
        )
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.MISSING_DATA}

    @patch.object(AppIntegrityService, "obtain_verdict")
    def test_successful_integrity_check_new_device(self, obtain_verdict_mock, client):
        raw_verdict = self._load_verdict_from_file("utils/tests/data/success_integrity_response.json")

        obtain_verdict_mock.return_value = raw_verdict["tokenPayloadExternal"]

        response = client.post(
            self.url,
            data={
                "cc_device_id": "new_device_id",
                "request_id": "test_uuid",
            },
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="aGVsbG8gd29scmQgdGhlcmU",
        )

        assert response.status_code == 200
        assert response.json() == {"result_code": "passed"}

        sample = DeviceIntegritySample.objects.get(request_id="test_uuid")
        assert sample.google_verdict == raw_verdict["tokenPayloadExternal"]
        assert sample.passed
        assert sample.passed_request_check
        assert sample.passed_app_integrity_check
        assert sample.passed_device_integrity_check
        assert sample.passed_account_details_check
        assert not sample.is_demo_user

    @patch.object(AppIntegrityService, "obtain_verdict")
    @patch.object(AppIntegrityService, "analyze_verdict")
    def test_successful_integrity_check_existing_device(self, analyze_verdict_mock, obtain_verdict_mock, client):
        existing_sample = DeviceIntegritySample.objects.create(
            request_id="test_uuid",
            device_id="existing_device_id",
            google_verdict={"old": "verdict"},
            passed=False,
            passed_request_check=False,
            passed_app_integrity_check=True,
            passed_device_integrity_check=True,
            passed_account_details_check=True,
            is_demo_user=False,
        )

        raw_verdict = self._load_verdict_from_file("utils/tests/data/success_integrity_response.json")
        obtain_verdict_mock.return_value = raw_verdict["tokenPayloadExternal"]
        analyze_verdict_mock.return_value = None

        response = client.post(
            self.url,
            data={
                "cc_device_id": "existing_device_id",
                "request_id": "test_uuid",
            },
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="aGVsbG8gd29scmQgdGhlcmU",
        )

        assert response.status_code == 200
        assert response.json() == {"result_code": None}

        existing_sample.refresh_from_db()
        assert existing_sample.google_verdict != raw_verdict["tokenPayloadExternal"]
        assert not existing_sample.passed
        assert not existing_sample.passed_request_check
        assert existing_sample.passed_app_integrity_check
        assert existing_sample.passed_device_integrity_check
        assert existing_sample.passed_account_details_check
        assert not existing_sample.is_demo_user

    @patch.object(AppIntegrityService, "obtain_verdict")
    @patch.object(AppIntegrityService, "analyze_verdict")
    def test_demo_user_detection(self, analyze_verdict_mock, obtain_verdict_mock, client):
        raw_verdict = self._load_verdict_from_file("utils/tests/data/success_integrity_response.json")
        obtain_verdict_mock.return_value = raw_verdict["tokenPayloadExternal"]
        analyze_verdict_mock.return_value = None

        response = client.post(
            self.url,
            data={
                "cc_device_id": "demo_device_id",
                "request_id": "test_uuid",
                "phone_number": TEST_NUMBER_PREFIX + "1234567",
            },
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="aGVsbG8gd29scmQgdGhlcmU",
        )
        assert response.status_code == 200

        sample = DeviceIntegritySample.objects.get(request_id="test_uuid")
        assert sample.is_demo_user is True

    @patch.object(AppIntegrityService, "obtain_verdict")
    def test_integrity_request_error(self, obtain_verdict_mock, client):
        raw_verdict = self._load_verdict_from_file("utils/tests/data/request_hash_mismatch_response.json")
        obtain_verdict_mock.return_value = raw_verdict["tokenPayloadExternal"]

        response = client.post(
            self.url,
            data={
                "cc_device_id": "failed_device_id",
                "request_id": "test_uuid",
            },
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="aGVsbG8gd29scmQgdGhlcmU",
        )

        assert response.status_code == 200
        assert response.json() == {"result_code": "failed"}

        sample = DeviceIntegritySample.objects.get(request_id="test_uuid")
        assert not sample.passed
        assert not sample.passed_request_check
        assert sample.passed_app_integrity_check
        assert sample.passed_device_integrity_check
        assert sample.passed_account_details_check

    @patch.object(AppIntegrityService, "obtain_verdict")
    def test_device_integrity_error(self, obtain_verdict_mock, client):
        raw_verdict = self._load_verdict_from_file("utils/tests/data/device_integrity_unmet_response.json")
        obtain_verdict_mock.return_value = raw_verdict["tokenPayloadExternal"]

        response = client.post(
            self.url,
            data={
                "cc_device_id": "device_failed_device_id",
                "request_id": "test_uuid",
            },
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="aGVsbG8gd29scmQgdGhlcmU",
        )

        assert response.status_code == 200
        assert response.json() == {"result_code": "failed"}

        sample = DeviceIntegritySample.objects.get(request_id="test_uuid")
        assert not sample.passed
        assert sample.passed_request_check
        assert sample.passed_app_integrity_check
        assert not sample.passed_device_integrity_check
        assert sample.passed_account_details_check

    @patch.object(AppIntegrityService, "obtain_verdict")
    def test_account_details_error(self, obtain_verdict_mock, client):
        raw_verdict = self._load_verdict_from_file("utils/tests/data/unlicensed_response.json")
        obtain_verdict_mock.return_value = raw_verdict["tokenPayloadExternal"]

        response = client.post(
            self.url,
            data={
                "cc_device_id": "account_failed_device_id",
                "request_id": "test_uuid",
            },
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="aGVsbG8gd29scmQgdGhlcmU",
        )

        assert response.status_code == 200
        assert response.json() == {"result_code": "failed"}

        sample = DeviceIntegritySample.objects.get(request_id="test_uuid")
        assert not sample.passed
        assert sample.passed_request_check
        assert sample.passed_app_integrity_check
        assert sample.passed_device_integrity_check
        assert not sample.passed_account_details_check

    @patch.object(AppIntegrityService, "obtain_verdict")
    def test_multiple_checks_fails(self, obtain_verdict_mock, client):
        raw_verdict = self._load_verdict_from_file(
            "utils/tests/data/unlicensed_and_device_error_integrity_response.json"
        )
        obtain_verdict_mock.return_value = raw_verdict["tokenPayloadExternal"]

        response = client.post(
            self.url,
            data={
                "cc_device_id": "account_failed_device_id",
                "request_id": "test_uuid",
            },
            HTTP_CC_INTEGRITY_TOKEN="test_token",
            HTTP_CC_REQUEST_HASH="aGVsbG8gd29scmQgdGhlcmU",
        )

        assert response.status_code == 200
        assert response.json() == {"result_code": "failed"}

        sample = DeviceIntegritySample.objects.get(request_id="test_uuid")
        assert not sample.passed
        assert sample.passed_request_check
        assert sample.passed_app_integrity_check
        assert not sample.passed_device_integrity_check
        assert not sample.passed_account_details_check


@pytest.mark.django_db
class TestGenerateManualOTP:
    url = reverse("generate_manual_otp")

    def _create_session_phone_device(self, expires, phone_number):
        config_session = ConfigurationSessionFactory.create(expires=expires, phone_number=phone_number)
        return SessionPhoneDeviceFactory.create(session=config_session, phone_number=phone_number)

    def test_success(self, authed_client):
        phone_number = Faker().phone_number()
        now = datetime.now()
        self._create_session_phone_device(expires=now + timedelta(days=1), phone_number=phone_number)
        newest_session_phone_device = self._create_session_phone_device(
            expires=now + timedelta(days=2), phone_number=phone_number
        )
        SessionPhoneDeviceFactory.create()

        token = newest_session_phone_device.token
        response = authed_client.get(self.url, data={"phone_number": phone_number})
        assert response.status_code == 200

        newest_session_phone_device.refresh_from_db()
        assert response.json() == {
            "otp": newest_session_phone_device.token,
        }
        assert newest_session_phone_device.has_manual_otp is True
        assert newest_session_phone_device.token == token  # A new token should not be generated

    def test_no_auth(self, client):
        response = client.get(self.url)
        assert response.status_code == 403

    def test_no_phone_number(self, authed_client):
        response = authed_client.get(self.url)
        assert response.status_code == 400
        assert response.json() == {"error_code": ErrorCodes.MISSING_DATA}

    def test_no_session(self, authed_client, user):
        response = authed_client.get(self.url, data={"phone_number": user.phone_number.raw_input})
        assert response.status_code == 404
        assert response.json() == {"error_code": ErrorCodes.SESSION_NOT_FOUND}

    def test_session_expired(self, authed_client, user):
        phone_number = Faker().phone_number()
        self._create_session_phone_device(expires=datetime.now() - timedelta(days=1), phone_number=phone_number)
        response = authed_client.get(self.url, data={"phone_number": phone_number})
        assert response.status_code == 404
        assert response.json() == {"error_code": ErrorCodes.SESSION_NOT_FOUND}


@pytest.mark.django_db
class TestFetchUserCounts:
    def test_no_auth(self, client):
        response = client.get(reverse("fetch_user_counts"))
        assert response.status_code == 403

    def test_success(self, authed_client):
        response = authed_client.get(reverse("fetch_user_counts"))
        assert response.status_code == 200
        assert "total_users" in response.json()
        assert "non_invited_users" in response.json()

        total_users_response = response.json()["total_users"]
        non_invited_users_response = response.json()["non_invited_users"]

        current_month = list(total_users_response.keys())[0]
        assert total_users_response[current_month] == 1
        assert non_invited_users_response == {}

    def test_success_with_multiple_users(self, authed_client):
        # Create 5 ConnectUsers without any ConfigurationSessions (historical users)
        UserFactory.create_batch(5)

        # Create ConfigurationSessions for invited and non-invited users and link ConnectUsers to them
        invited_sessions = ConfigurationSessionFactory.create_batch(3, invited_user=True)
        for session in invited_sessions:
            UserFactory(phone_number=session.phone_number)

        non_invited_sessions = ConfigurationSessionFactory.create_batch(3, invited_user=False)
        for session in non_invited_sessions:
            UserFactory(phone_number=session.phone_number)

        response = authed_client.get(reverse("fetch_user_counts"))
        assert response.status_code == 200

        total_users_response = response.json()["total_users"]
        non_invited_users_response = response.json()["non_invited_users"]
        current_month = list(total_users_response.keys())[0]

        assert total_users_response[current_month] == (
            1 + 5 + 3 + 3
        )  # initial user + historical + invited + non-invited
        assert non_invited_users_response[current_month] == 3

    def test_multiple_users_with_phone_number_reuse(self, authed_client):
        """
        This test makes sure that if a phone number was used by multiple users over time,
        only the latest user is counted.
        """
        # Set up a user that changed phone numbers
        configuration_sessions = ConfigurationSessionFactory.create_batch(2, invited_user=False)
        UserFactory(phone_number=configuration_sessions[0].phone_number, is_active=False)
        UserFactory(phone_number=configuration_sessions[1].phone_number, is_active=True)

        session = ConfigurationSessionFactory(phone_number=configuration_sessions[0].phone_number, invited_user=False)
        UserFactory(phone_number=session.phone_number, is_active=True)

        response = authed_client.get(reverse("fetch_user_counts"))
        assert response.status_code == 200

        total_users_response = response.json()["total_users"]
        non_invited_users_response = response.json()["non_invited_users"]
        current_month = list(total_users_response.keys())[0]

        assert total_users_response[current_month] == 4
        assert non_invited_users_response[current_month] == 2

    def test_failed_non_invited_session_is_not_counted_when_invited(self, authed_client):
        """
        This test makes sure that if a user was initially non-invited and failed to sign up,
        but then later became invited and sign up afterwards, they are not counted.
        """
        # Create a non-invited session, but no user to simulate "failed" signup
        non_invited_session = ConfigurationSessionFactory(
            invited_user=False, expires=datetime.now() - timedelta(hours=48)
        )

        # Create an invited user with the same phone number, who signed up 1 day later
        invited_session = ConfigurationSessionFactory(
            phone_number=non_invited_session.phone_number,
            invited_user=True,
            expires=datetime.now() - timedelta(hours=24),
        )
        # User completed signup 1 hour before session expiry
        UserFactory(
            phone_number=invited_session.phone_number,
            date_joined=datetime.now() - timedelta(hours=25),
            is_active=True,
        )

        response = authed_client.get(reverse("fetch_user_counts"))
        assert response.status_code == 200

        total_users_response = response.json()["total_users"]
        non_invited_users_response = response.json()["non_invited_users"]
        current_month = list(total_users_response.keys())[0]

        assert total_users_response[current_month] == 2
        assert non_invited_users_response == {}


@pytest.mark.django_db
class TestFetchUserAnalytics:
    url = reverse("fetch_user_analytics")

    def test_no_auth(self, client):
        response = client.post(self.url)
        assert response.status_code == 403

    def test_success_single_user(self, authed_client, user, credential_issuing_authority):
        # Create a credential for the user
        cred = CredentialFactory(issuer=credential_issuing_authority)
        UserCredentialFactory(user=user, credential=cred, accepted=True)

        cred_2 = CredentialFactory(issuer=credential_issuing_authority)
        UserCredentialFactory(user=user, credential=cred_2, accepted=False)

        # Create a channel and message for the user
        channel = ChannelFactory(connect_user=user)
        MessageFactory(
            channel=channel,
            direction=MessageDirection.SERVER,
            timestamp=datetime.now(),
            content={"text": "test message"},
        )

        response = authed_client.post(self.url, data={"usernames": [user.username]})
        assert response.status_code == 200
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["username"] == user.username
        assert data[0]["has_viewed_work_history"] is True
        assert data[0]["has_sent_message"] is not None

    def test_success_multiple_users(self, authed_client, credential_issuing_authority):
        user1 = UserFactory(is_active=True)
        user2 = UserFactory(is_active=True)
        user3 = UserFactory(is_active=True)

        # User 1: Has viewed work history
        cred1 = CredentialFactory(issuer=credential_issuing_authority)
        UserCredentialFactory(user=user1, credential=cred1, accepted=True)

        # User 2: Has sent message
        channel2 = ChannelFactory(connect_user=user2)
        MessageFactory(channel=channel2, direction=MessageDirection.SERVER, content={"text": "test message 2"})

        # User 3: No analytics data

        response = authed_client.post(self.url, data={"usernames": [user1.username, user2.username, user3.username]})
        assert response.status_code == 200
        data = response.json()["data"]
        assert len(data) == 3

        user1_data = next(item for item in data if item["username"] == user1.username)
        assert user1_data["has_viewed_work_history"]
        assert user1_data["has_sent_message"] is None

        user2_data = next(item for item in data if item["username"] == user2.username)
        assert not user2_data["has_viewed_work_history"]
        assert user2_data["has_sent_message"] is not None

        user3_data = next(item for item in data if item["username"] == user3.username)
        assert not user3_data["has_viewed_work_history"]
        assert user3_data["has_sent_message"] is None

    def test_no_users_found(self, authed_client):
        response = authed_client.post(self.url, data={"usernames": ["nonexistent_user"]})
        assert response.status_code == 200
        assert response.json()["data"] == []

    def test_inactive_user_not_counted(self, authed_client, credential_issuing_authority):
        user = UserFactory(is_active=False)
        cred = CredentialFactory(issuer=credential_issuing_authority)
        UserCredentialFactory(user=user, credential=cred, accepted=True)

        response = authed_client.post(self.url, data={"usernames": [user.username]})
        assert response.status_code == 200
        assert response.json()["data"] == []
