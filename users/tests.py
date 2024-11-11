import pytest
from django.urls import reverse
from fcm_django.models import FCMDevice

from users.factories import CredentialFactory
from users.fcm_utils import create_update_device
from users.models import ConnectUser


@pytest.mark.django_db
def test_registration(client):
    response = client.post('/users/register', {
        'username': 'testuser',
        'password': 'testpass',
        'phone_number': '+27734567657',
    })
    assert response.status_code == 200, response.content
    user = ConnectUser.objects.get(username='testuser')
    assert user.phone_number == '+27734567657'


@pytest.mark.django_db
def test_registration_with_fcm_token(client):
    response = client.post('/users/register', {
        'username': 'testuser',
        'password': 'testpass',
        'phone_number': '+27734567657',
        'fcm_token': 'testtoken'
    })
    assert response.status_code == 200, response.content
    user = ConnectUser.objects.get(username='testuser')
    device = FCMDevice.objects.get(user=user)
    assert device.registration_id == 'testtoken'
    assert device.type == 'android'
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
    assert active_device.registration_id == 'testtoken1'


def test_create_update_device__update_old_device(user):
    test_create_update_device__new_device(user)

    # attempt to updated old device
    response = create_update_device(user, "testtoken")
    assert response.status_code == 202, response.content
    assert response.content == b'{"warning": "Another device is already active"}'


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
