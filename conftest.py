import base64

import pytest
from rest_framework.test import APIClient

from users.factories import UserFactory, FCMDeviceFactory


@pytest.fixture
def user(db):
    return UserFactory()


@pytest.fixture
def fcm_device(user):
    return FCMDeviceFactory(user=user)


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def auth_device(user):
    """
    Create the Basic Authentication credentials for the test user.
    """
    credentials = f"{user.username}:testpass".encode("utf-8")
    base64_credentials = base64.b64encode(credentials).decode("utf-8")
    cred = f"Basic {base64_credentials}"
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=cred)
    return client
