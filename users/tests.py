import pytest
from fcm_django.models import FCMDevice

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
