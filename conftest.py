import base64

import pytest
from oauth2_provider.models import Application
from rest_framework.test import APIClient

from users.factories import FCMDeviceFactory, UserFactory


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
def auth_device(user, api_client):
    """
    Create the Basic Authentication credentials for the test user.
    """
    credentials = f"{user.username}:testpass".encode()
    base64_credentials = base64.b64encode(credentials).decode("utf-8")
    cred = f"Basic {base64_credentials}"
    api_client.credentials(HTTP_AUTHORIZATION=cred)
    return api_client


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
def authed_client(api_client, oauth_app):
    auth = f"{oauth_app.client_id}:{oauth_app.raw_client_secret}".encode()
    credentials = base64.b64encode(auth).decode("utf-8")
    api_client.defaults["HTTP_AUTHORIZATION"] = "Basic " + credentials
    return api_client
