import pytest

from users.factories import UserFactory, FCMDeviceFactory


@pytest.fixture
def user(db):
    return UserFactory()


@pytest.fixture
def fcm_device(user):
    return FCMDeviceFactory(user=user)
