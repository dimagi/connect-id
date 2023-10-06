import pytest
from fcm_django.models import FCMDevice

from users.models import ConnectUser


@pytest.fixture
def user(db):
    return ConnectUser.objects.create_user(
        username='testuser',
        password='testpass',
        phone_number='+27734567657',
    )


@pytest.fixture
def fcm_device(user):
    return FCMDevice.objects.create(
        user=user,
        registration_id='testregid',
        type='android',
    )