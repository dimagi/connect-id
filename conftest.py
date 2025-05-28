import base64
from datetime import timedelta

import pytest
from django.utils.timezone import now
from oauth2_provider.models import Application
from rest_framework.test import APIClient

from users.auth import SessionTokenAuthentication
from users.factories import ConfigurationSessionFactory, FCMDeviceFactory, RecoveryStatusFactory, UserFactory


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


@pytest.fixture
def authed_client_token(authed_client, valid_token):
    authed_client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {valid_token.key}"
    return authed_client


@pytest.fixture
def recovery_status():
    return RecoveryStatusFactory()


@pytest.fixture
def recovery_status_with_expired_token_user():
    status = RecoveryStatusFactory()
    status.user.deactivation_token_valid_until = now() - timedelta(days=1)
    status.user.save()
    return status


@pytest.fixture
def token_auth():
    return SessionTokenAuthentication()


@pytest.fixture
def valid_token(user):
    return ConfigurationSessionFactory(
        phone_number=user.phone_number,
        is_phone_validated=True,
    )


@pytest.fixture
def expired_token():
    expires = now() - timedelta(days=2)
    return ConfigurationSessionFactory(expires=expires)
