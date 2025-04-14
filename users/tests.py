import json
from datetime import timedelta
from unittest import mock

import pytest
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from fcm_django.models import FCMDevice

from users.const import NO_RECOVERY_PHONE_ERROR, ErrorCodes
from users.factories import CredentialFactory
from users.fcm_utils import create_update_device
from users.models import ConnectUser, PhoneDevice, RecoveryStatus


@pytest.mark.django_db
def test_registration(client):
    response = client.post(
        "/users/register",
        {
            "username": "testuser",
            "password": "testpass",
            "phone_number": "+27734567657",
        },
    )
    assert response.status_code == 200, response.content
    user = ConnectUser.objects.get(username="testuser")
    assert user.phone_number == "+27734567657"


@pytest.mark.django_db
def test_registration_with_fcm_token(client):
    response = client.post(
        "/users/register",
        {"username": "testuser", "password": "testpass", "phone_number": "+27734567657", "fcm_token": "testtoken"},
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


class TestValidateSecondaryPhone:
    def test_no_recovery_phone(self, auth_device):
        endpoint = reverse("validate_secondary_phone")
        response = auth_device.post(endpoint)
        assert isinstance(response, JsonResponse)
        assert response.status_code == 400
        assert response.json() == {"error": NO_RECOVERY_PHONE_ERROR}


class TestConfirmSecondaryOTP:
    def test_no_recovery_phone(self, auth_device, user):
        endpoint = reverse("confirm_secondary_otp")
        response = auth_device.post(endpoint)
        assert isinstance(response, JsonResponse)
        assert response.status_code == 400
        assert response.json() == {"error": NO_RECOVERY_PHONE_ERROR}


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
    def test_success(self, mock_initiate_deactivation, client, recovery_status):
        response = client.post(self.endpoint, self.get_post_data(recovery_status.user, recovery_status))
        assert response.status_code == 200
        assert isinstance(response, HttpResponse)
        mock_initiate_deactivation.assert_called()

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

    def test_expired_deactivation_token(self, client, user_with_expired_deactivation_token, recovery_status):
        response = client.post(
            self.endpoint, self.get_post_data(user_with_expired_deactivation_token, recovery_status)
        )
        self.assert_fail_response(
            response,
            expected_code=ErrorCodes.TOKEN_EXPIRED,
        )
