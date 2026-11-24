import base64
from datetime import timedelta

import pytest
from constance import config as constance_config
from constance.backends.memory import MemoryBackend
from django.conf import settings
from django.core.cache import caches
from django.utils.functional import empty
from django.utils.timezone import now
from oauth2_provider.models import AccessToken, Application
from rest_framework.test import APIClient

from users.auth import SessionTokenAuthentication
from users.factories import (
    ConfigurationSessionFactory,
    FCMDeviceFactory,
    IssuingAuthorityFactory,
    ServerKeysFactory,
    UserFactory,
)


@pytest.fixture(autouse=True)
def production_behaviour(settings, tmp_path):
    """Tests exercise the production code paths whatever the developer's .env says.

    The exceptions: each file storage bucket is pointed at its own temp directory so no test touches
    S3, and the rate limit and throttle caches are emptied in-memory caches so no test needs Redis. Tests of the
    opt-outs turn them on themselves.
    """
    settings.PLAYSTORE_INTEGRITY_DISABLED = False
    settings.CONNECT_DISABLED = False
    settings.SMS_DEFAULT_VENDOR = "twilio"
    settings.RICH_MESSAGING_ENABLED = False
    settings.CACHES = {
        **settings.CACHES,
        "rate_limit": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "rate_limit"},
        "throttle": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "throttle"},
    }
    caches["rate_limit"].clear()
    caches["throttle"].clear()
    settings.STORAGES = {
        **settings.STORAGES,
        **{
            alias: {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": tmp_path / alias, "allow_overwrite": True},
            }
            for alias in settings.FILE_STORAGE_BUCKETS
        },
    }


@pytest.fixture(autouse=True)
def config(monkeypatch):
    """Runtime settings (django-constance), held in memory and reset for each test.

    Set one with `config.PHONE_COUNTRY_HOURLY_LIMIT = 1`. Unset ones read as their CONSTANCE_CONFIG default.
    """
    backend = MemoryBackend()
    backend._storage = {}
    # Patch the Config that constance's LazyConfig wraps, not the lazy proxy: `_backend` lives on the wrapped
    # object, and from pytest 9.2 undoing a patch on the proxy deletes the real `_backend` instead of restoring it.
    if constance_config._wrapped is empty:
        constance_config._setup()
    monkeypatch.setattr(constance_config._wrapped, "_backend", backend)
    return constance_config


@pytest.fixture
def user(db):
    return UserFactory()


@pytest.fixture
def locked_user(db):
    return UserFactory(is_active=False, is_locked=True)


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
def oauth_app(db):
    application = Application(
        name="Test Application HQ",
        redirect_uris="http://localhost",
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
def credential_issuing_authority():
    issuing_credentials_auth = ServerKeysFactory()
    credential_issuing_authority = IssuingAuthorityFactory(server_credentials=issuing_credentials_auth)
    return credential_issuing_authority


@pytest.fixture
def credential_issuing_client(api_client, credential_issuing_authority):
    auth = (
        f"{credential_issuing_authority.server_credentials.client_id}:"
        f"{credential_issuing_authority.server_credentials.secret_key}"
    ).encode()
    credentials = base64.b64encode(auth).decode("utf-8")
    api_client.defaults["HTTP_AUTHORIZATION"] = "Basic " + credentials
    return api_client


@pytest.fixture
def authed_client_token(authed_client, valid_token):
    authed_client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {valid_token.key}"
    return authed_client


@pytest.fixture
def authed_client_token_v3(authed_client_token):
    authed_client_token.defaults["HTTP_ACCEPT"] = f"application/json; version={settings.API_VERSION.V3}"
    return authed_client_token


@pytest.fixture
def token_auth():
    return SessionTokenAuthentication()


@pytest.fixture
def valid_token(user):
    return ConfigurationSessionFactory(
        phone_number=user.phone_number,
        is_phone_validated=True,
        invited_user=True,
    )


@pytest.fixture
def expired_token():
    expires = now() - timedelta(days=2)
    return ConfigurationSessionFactory(expires=expires)


@pytest.fixture
def user_bearer_client(user, oauth_app, api_client):
    """APIClient authenticated with an OAuth2 Bearer token for the test user."""
    token = AccessToken.objects.create(
        user=user,
        application=oauth_app,
        token="test-access-token",
        expires=now() + timedelta(hours=1),
        scope="read write",
    )
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.token}")
    return api_client


@pytest.fixture
def session_client():
    """Factory fixture — call with a ConfigurationSession to get an authenticated client."""

    def _make(session):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {session.key}")
        return client

    return _make
