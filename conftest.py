import base64

import pytest
from oauth2_provider.models import Application
from rest_framework.test import APIClient

from users.factories import UserFactory, FCMDeviceFactory
from messaging.factories import ServerFactory

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

@pytest.fixture
def oauth_app(user):
    application = Application(
        name="Test Application",
        redirect_uris="http://localhost",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
    )
    application.raw_client_secret = application.client_secret
    application.save()
    return application


@pytest.fixture
def server(oauth_app):
    return ServerFactory(oauth_application=oauth_app)


@pytest.fixture
def authed_client(client, oauth_app):
    auth = f'{oauth_app.client_id}:{oauth_app.raw_client_secret}'.encode('utf-8')
    credentials = base64.b64encode(auth).decode('utf-8')
    client.defaults['HTTP_AUTHORIZATION'] = 'Basic ' + credentials
    return client
