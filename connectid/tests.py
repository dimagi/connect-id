"""Tests for project-level wiring: Firebase app setup and WSGI/ASGI entrypoints.

The Firebase tests cover the code path that only runs when ``FCM_PRIVATE_KEY`` is set, which is
never the case locally or in CI. Without them the credential construction and
``initialize_app`` call would first execute in production.
"""

import importlib

import firebase_admin
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from firebase_admin import messaging

from connectid.firebase import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    build_service_account_credentials,
    initialize_firebase_app,
)

PROJECT_ID = "connectid-test-project"
CLIENT_EMAIL = "fcm@connectid-test-project.iam.gserviceaccount.com"


def _generate_private_key_pem() -> str:
    """A throwaway RSA key, so ``credentials.Certificate`` accepts the service account."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def service_account() -> dict:
    return build_service_account_credentials(
        project_id=PROJECT_ID,
        private_key_id="test-key-id",
        private_key=_generate_private_key_pem(),
        client_email=CLIENT_EMAIL,
        client_id="1234567890",
        client_x509_cert_url=f"https://www.googleapis.com/robot/v1/metadata/x509/{CLIENT_EMAIL}",
    )


@pytest.fixture
def firebase_app(service_account, request):
    """A named app, so tests never clobber the unnamed default app production uses."""
    app = initialize_firebase_app(service_account, name=f"test-{request.node.name}")
    yield app
    firebase_admin.delete_app(app)


class TestInitializeFirebaseApp:
    def test_builds_an_app_from_the_service_account(self, firebase_app):
        """The v1 API authenticates per-app from the service account, so this is the FCM entrypoint."""
        assert firebase_app.project_id == PROJECT_ID
        assert firebase_app.credential.service_account_email == CLIENT_EMAIL

    @pytest.mark.parametrize(
        ("timeout_kwargs", "expected_timeout"),
        [({}, DEFAULT_HTTP_TIMEOUT_SECONDS), ({"http_timeout_seconds": 7}, 7)],
        ids=["default", "explicit"],
    )
    def test_applies_the_http_timeout(self, service_account, request, timeout_kwargs, expected_timeout):
        app = initialize_firebase_app(service_account, name=f"test-{request.node.name}", **timeout_kwargs)
        try:
            assert app.options.get("httpTimeout") == expected_timeout
        finally:
            firebase_admin.delete_app(app)

    def test_messaging_service_targets_the_http_v1_endpoint(self, firebase_app):
        """Where a malformed credential or unsupported option surfaces, short of a network call.

        Also pins that sends go to the HTTP v1 endpoint for our project rather than the legacy API.
        """
        service = messaging._get_messaging_service(firebase_app)

        assert service._fcm_url == f"https://fcm.googleapis.com/v1/projects/{PROJECT_ID}/messages:send"
        assert service._client.timeout == DEFAULT_HTTP_TIMEOUT_SECONDS

    def test_rejects_a_malformed_private_key(self, service_account, request):
        service_account["private_key"] = "not-a-pem-key"
        with pytest.raises(ValueError):
            initialize_firebase_app(service_account, name=f"test-{request.node.name}")


class TestApplicationEntrypoints:
    """Both are only exercised by a real server boot, so a Django bump can break them unnoticed."""

    @pytest.mark.parametrize("module_path", ["connectid.wsgi", "connectid.asgi"])
    def test_application_loads(self, module_path):
        module = importlib.import_module(module_path)

        assert module.application is not None
