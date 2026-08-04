import base64
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from django.urls import reverse
from django.utils.timezone import now
from oauth2_provider.models import AccessToken, Application, RefreshToken
from rest_framework.test import APIClient

from users.const import ErrorCodes
from users.factories import UserDeviceInfoFactory, UserFactory
from users.oauth import ConnectOAuth2Validator, LoginFromDifferentDeviceError


def _oauth_request_mock():
    return MagicMock(uri="/token", http_method="POST", decoded_body=[], headers={})


def _basic_auth_header(client_id, client_secret):
    creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return f"Basic {creds}"


def _post_token(client, application, data):
    return client.post(
        reverse("oauth2_provider:token"),
        data=data,
        HTTP_AUTHORIZATION=_basic_auth_header(application.client_id, application.raw_client_secret),
    )


@pytest.fixture
def password_grant_app(db):
    application = Application(
        name="Test Password Grant App",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_PASSWORD,
    )
    application.raw_client_secret = application.client_secret
    application.save()
    return application


@pytest.mark.django_db
class TestConnectOAuth2ValidatorUser:
    def setup_method(self):
        self.validator = ConnectOAuth2Validator()

    def test_successful_auth_updates_last_accessed(self):
        user = UserFactory()
        raw_password = "testpass"
        old_time = now() - timedelta(days=1)
        device = UserDeviceInfoFactory(user=user, raw_password=raw_password, last_accessed=old_time)

        result = self.validator.validate_user(
            user.username, raw_password, client=MagicMock(), request=_oauth_request_mock()
        )
        assert result is True
        device.refresh_from_db()
        assert device.last_accessed > old_time

    def test_failed_auth_different_device_raises_custom_error(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="old_pass",
            device="Old Phone",
            last_accessed=now() - timedelta(days=5),
        )
        UserDeviceInfoFactory(
            user=user,
            raw_password="new_pass",
            device="New Phone",
            last_accessed=now(),
        )

        with pytest.raises(LoginFromDifferentDeviceError) as exc_info:
            self.validator.validate_user(user.username, "old_pass", client=MagicMock(), request=_oauth_request_mock())
        assert exc_info.value.error == ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE
        assert dict(exc_info.value.twotuples)["error_code"] == ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE

    def test_failed_auth_no_device_match(self):
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="some_pass")

        result = self.validator.validate_user(
            user.username, "totally_wrong", client=MagicMock(), request=_oauth_request_mock()
        )
        assert result is False

    def test_failed_auth_old_access_returns_false(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user,
            raw_password="old_pass",
            device="Old Phone",
            last_accessed=now() - timedelta(days=60),
        )
        UserDeviceInfoFactory(
            user=user,
            raw_password="new_pass",
            device="New Phone",
            last_accessed=now() - timedelta(days=35),
        )

        result = self.validator.validate_user(
            user.username, "old_pass", client=MagicMock(), request=_oauth_request_mock()
        )
        assert result is False


@pytest.mark.django_db
class TestConnectOAuth2ValidatorClaims:
    def setup_method(self):
        self.validator = ConnectOAuth2Validator()

    def test_get_additional_claims_returns_expected_claims(self):
        user = UserFactory(name="Jane Doe")
        request = MagicMock(user=user)

        claims = self.validator.get_additional_claims(request)

        assert claims == {
            "sub": user.username,
            "name": user.name,
            "phone": user.phone_number.as_e164,
            "is_active": user.is_active,
        }

    @pytest.mark.parametrize("claim", ["sub", "name", "phone", "is_active"])
    def test_oidc_claim_scope_gates_custom_claims_behind_openid(self, claim):
        assert ConnectOAuth2Validator.oidc_claim_scope[claim] == "openid"


@pytest.mark.django_db
class TestOAuth2TokenEndpoint:
    def test_password_grant_issues_token_for_valid_credentials(self, client, password_grant_app):
        raw_password = "testpass123"
        user = UserFactory(password=raw_password)
        UserDeviceInfoFactory(user=user, raw_password=raw_password)

        response = _post_token(
            client,
            password_grant_app,
            {
                "grant_type": "password",
                "username": user.username,
                "password": raw_password,
                "scope": "openid sync",
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert "access_token" in body
        assert body["scope"] == "openid sync"

    def test_password_grant_surfaces_login_from_different_device_error(self, client, password_grant_app):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user, raw_password="old_pass", device="Old Phone", last_accessed=now() - timedelta(days=5)
        )
        UserDeviceInfoFactory(user=user, raw_password="new_pass", device="New Phone", last_accessed=now())

        response = _post_token(
            client,
            password_grant_app,
            {"grant_type": "password", "username": user.username, "password": "old_pass"},
        )

        assert response.status_code == 400
        assert response.json()["error_code"] == ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE

    def test_client_credentials_grant_issues_token(self, client, oauth_app):
        response = _post_token(client, oauth_app, {"grant_type": "client_credentials"})

        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_refresh_token_grant_issues_new_access_token(self, client, password_grant_app):
        raw_password = "testpass123"
        user = UserFactory(password=raw_password)
        UserDeviceInfoFactory(user=user, raw_password=raw_password)

        initial = _post_token(
            client,
            password_grant_app,
            {"grant_type": "password", "username": user.username, "password": raw_password, "scope": "sync"},
        ).json()
        assert "refresh_token" in initial

        response = _post_token(
            client,
            password_grant_app,
            {"grant_type": "refresh_token", "refresh_token": initial["refresh_token"]},
        )

        assert response.status_code == 200
        body = response.json()
        assert "access_token" in body
        assert body["access_token"] != initial["access_token"]


@pytest.mark.django_db
class TestOAuth2TokenRevocation:
    """Pins the behavior `deactivate_account` relies on (users/views.py) to invalidate sessions."""

    def test_revoke_deletes_the_token_row(self, oauth_app, user):
        token = AccessToken.objects.create(
            user=user, application=oauth_app, token="to-be-revoked", expires=now() + timedelta(hours=1), scope="openid"
        )

        token.revoke()

        assert not AccessToken.objects.filter(token="to-be-revoked").exists()

    def test_revoked_access_token_no_longer_authenticates(self, oauth_app, user):
        token = AccessToken.objects.create(
            user=user, application=oauth_app, token="revoke-me", expires=now() + timedelta(hours=1), scope="openid"
        )
        api_client = APIClient()
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.token}")
        assert api_client.get(reverse("oauth2_provider:user-info")).status_code == 200

        token.revoke()

        response = api_client.get(reverse("oauth2_provider:user-info"))
        assert response.status_code in (401, 403)

    def test_revoke_token_endpoint_invalidates_a_live_access_token(self, client, password_grant_app):
        raw_password = "testpass123"
        user = UserFactory(password=raw_password)
        UserDeviceInfoFactory(user=user, raw_password=raw_password)
        issued = _post_token(
            client,
            password_grant_app,
            {"grant_type": "password", "username": user.username, "password": raw_password, "scope": "openid"},
        ).json()

        revoke_response = client.post(
            reverse("oauth2_provider:revoke-token"),
            data={"token": issued["access_token"]},
            HTTP_AUTHORIZATION=_basic_auth_header(password_grant_app.client_id, password_grant_app.raw_client_secret),
        )
        assert revoke_response.status_code == 200

        api_client = APIClient()
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {issued['access_token']}")
        response = api_client.get(reverse("oauth2_provider:user-info"))
        assert response.status_code in (401, 403)

    def test_token_revocation_used_by_deactivate_account(self, oauth_app, user):
        """Mirrors the revoke loop in users/views.py's deactivate_account view.

        AccessToken.revoke() hard-deletes the row, but RefreshToken.revoke() soft-deletes
        (sets `revoked`) and cascades to hard-delete its linked access token instead.
        """
        access_token = AccessToken.objects.create(
            user=user, application=oauth_app, token="access-for-deactivation", expires=now() + timedelta(hours=1)
        )
        refresh_token = RefreshToken.objects.create(
            user=user, application=oauth_app, token="refresh-for-deactivation", access_token=access_token
        )

        tokens = list(AccessToken.objects.filter(user=user)) + list(RefreshToken.objects.filter(user=user))
        for token in tokens:
            token.revoke()

        assert not AccessToken.objects.filter(pk=access_token.pk).exists()
        refresh_token.refresh_from_db()
        assert refresh_token.revoked is not None


@pytest.mark.django_db
class TestOIDCDiscovery:
    def test_discovery_endpoint_exposes_expected_metadata(self, client):
        response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))

        assert response.status_code == 200
        data = response.json()
        assert data["token_endpoint"].endswith("/o/token/")
        assert data["userinfo_endpoint"].endswith("/o/userinfo/")

    @pytest.mark.parametrize("scope", ["openid", "sync"])
    def test_discovery_advertises_configured_scopes(self, client, scope):
        response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))

        assert scope in response.json()["scopes_supported"]


@pytest.mark.django_db
class TestOAuth2Introspection:
    @pytest.mark.parametrize("token_exists,expected_active", [(True, True), (False, False)])
    def test_introspect_reports_token_active_state(self, client, oauth_app, user, token_exists, expected_active):
        token_value = "introspect-me" if token_exists else "does-not-exist"
        if token_exists:
            AccessToken.objects.create(
                user=user,
                application=oauth_app,
                token=token_value,
                expires=now() + timedelta(hours=1),
                scope="openid sync",
            )

        response = client.post(
            reverse("oauth2_provider:introspect"),
            data={"token": token_value},
            HTTP_AUTHORIZATION=_basic_auth_header(oauth_app.client_id, oauth_app.raw_client_secret),
        )

        assert response.status_code == 200
        body = response.json()
        assert body["active"] is expected_active
        if expected_active:
            assert body["username"] == user.username


@pytest.mark.django_db
class TestOIDCUserInfo:
    @pytest.mark.parametrize("scope,has_openid", [("openid sync", True), ("sync", False)])
    def test_userinfo_claims_depend_on_openid_scope(self, oauth_app, user, scope, has_openid):
        token = AccessToken.objects.create(
            user=user,
            application=oauth_app,
            token=f"userinfo-{scope.replace(' ', '-')}",
            expires=now() + timedelta(hours=1),
            scope=scope,
        )
        api_client = APIClient()
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.token}")

        response = api_client.get(reverse("oauth2_provider:user-info"))

        if has_openid:
            assert response.status_code == 200
            body = response.json()
            assert body["sub"] == user.username
            assert body["name"] == user.name
            assert body["phone"] == user.phone_number.as_e164
            assert body["is_active"] == user.is_active
        else:
            assert response.status_code in (401, 403)
