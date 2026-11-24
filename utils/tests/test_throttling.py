import base64

import pytest
from django.contrib.auth.models import AnonymousUser
from django.core.cache import caches
from django.urls import reverse
from oauth2_provider.models import Application
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework.views import APIView

from connectid import settings as project_settings
from messaging.factories import ServerFactory
from users.auth import IssuingCredentialsAuth, SessionTokenAuthentication
from users.factories import ConfigurationSessionFactory, IssuingAuthorityFactory, ServerKeysFactory, UserFactory
from utils.rest_framework import (
    ClientProtectedResourceAuth,
    MessagingServerAuth,
    ServiceAwareUserRateThrottle,
    SharedAnonRateThrottle,
)


@pytest.fixture(autouse=True)
def low_rate(monkeypatch):
    # The throttle cache is an emptied in-memory cache for each test (conftest)
    monkeypatch.setattr(ServiceAwareUserRateThrottle, "rate", "2/day", raising=False)
    monkeypatch.setattr(SharedAnonRateThrottle, "rate", "2/day", raising=False)


def basic_auth(client_id, secret):
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


def oauth_application():
    application = Application(
        name="Client",
        redirect_uris="http://localhost",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
    )
    application.raw_client_secret = application.client_secret
    application.save()
    return basic_auth(application.client_id, application.raw_client_secret)


def message_server():
    keys = ServerFactory(server_credentials=ServerKeysFactory()).server_credentials
    return basic_auth(keys.client_id, keys.secret_key)


def issuing_authority():
    keys = IssuingAuthorityFactory(server_credentials=ServerKeysFactory()).server_credentials
    return basic_auth(keys.client_id, keys.secret_key)


def make_view(auth_class):
    class View(APIView):
        authentication_classes = [auth_class]

        def get(self, request):
            return Response({})

    return View.as_view()


def call(view, authorization):
    request = APIRequestFactory().get("/", HTTP_AUTHORIZATION=authorization)
    return view(request).status_code


@pytest.mark.django_db
@pytest.mark.parametrize(
    "auth_class, make_caller",
    [
        (MessagingServerAuth, message_server),
        (ClientProtectedResourceAuth, oauth_application),
        (IssuingCredentialsAuth, issuing_authority),
    ],
)
def test_each_service_caller_has_its_own_bucket(auth_class, make_caller):
    view = make_view(auth_class)
    first, second = make_caller(), make_caller()

    assert [call(view, first) for _ in range(3)] == [200, 200, 429]
    # Before, every service caller shared the bucket keyed on pk None, so this was throttled too
    assert call(view, second) == 200


@pytest.mark.django_db
def test_message_servers_and_oauth_clients_do_not_share_a_bucket():
    server_view = make_view(MessagingServerAuth)
    client_view = make_view(ClientProtectedResourceAuth)
    server = message_server()

    assert [call(server_view, server) for _ in range(3)] == [200, 200, 429]
    assert call(client_view, oauth_application()) == 200


@pytest.mark.django_db
def test_send_fcm_is_throttled_per_server():
    url = reverse("messaging:send_fcm")
    body = {
        "channel": "00000000-0000-0000-0000-000000000000",
        "message_id": "x",
        "content": {"nonce": "n", "tag": "t", "ciphertext": "c"},
    }
    busy, other = APIClient(), APIClient()
    busy.credentials(HTTP_AUTHORIZATION=message_server())
    other.credentials(HTTP_AUTHORIZATION=message_server())

    statuses = [busy.post(url, body, format="json").status_code for _ in range(3)]
    assert statuses[-1] == 429 and 429 not in statuses[:-1]
    assert other.post(url, body, format="json").status_code != 429


@pytest.mark.django_db
def test_people_are_still_keyed_on_their_pk():
    user = UserFactory()
    request = APIRequestFactory().get("/")
    request.user = user

    assert ServiceAwareUserRateThrottle().get_cache_key(request, None) == f"throttle_user_{user.pk}"


def test_throttle_cache_is_shared_and_fails_soft():
    throttle_cache = project_settings.CACHES["throttle"]

    # The same Redis as the rate limit cache, which every worker and host shares
    assert throttle_cache["LOCATION"] == project_settings.CACHES["rate_limit"]["LOCATION"]
    assert throttle_cache["BACKEND"] == "utils.cache.FailSoftRedisCache"
    assert set(project_settings.REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"]) == {
        "utils.rest_framework.SharedAnonRateThrottle",
        "utils.rest_framework.ServiceAwareUserRateThrottle",
    }


@pytest.mark.django_db
def test_counts_go_to_the_throttle_cache_not_the_per_process_default():
    view = make_view(MessagingServerAuth)
    server = message_server()

    call(view, server)

    assert any("throttle_user_message_server" in key for key in caches["throttle"]._cache)
    assert not any("throttle_" in key for key in caches["default"]._cache)


@pytest.mark.django_db
def test_anonymous_callers_are_counted_in_the_throttle_cache():
    class OpenView(APIView):
        authentication_classes = []
        permission_classes = [AllowAny]

        def get(self, request):
            return Response({})

    view = OpenView.as_view()

    assert [view(APIRequestFactory().get("/")).status_code for _ in range(3)] == [200, 200, 429]
    assert any("throttle_anon_" in key for key in caches["throttle"]._cache)


@pytest.mark.django_db
def test_requests_are_allowed_while_redis_is_down(settings):
    settings.CACHES = {
        **settings.CACHES,
        "throttle": {
            "BACKEND": "utils.cache.FailSoftRedisCache",
            "LOCATION": "redis://127.0.0.1:1/0",
            "KEY_PREFIX": "throttle",
            "OPTIONS": {"socket_connect_timeout": 0.1, "socket_timeout": 0.1},
        },
    }
    view = make_view(MessagingServerAuth)
    server = message_server()

    assert [call(view, server) for _ in range(3)] == [200, 200, 200]


def session_bearer(phone_number):
    return f"Bearer {ConfigurationSessionFactory(phone_number=phone_number).key}"


@pytest.mark.django_db
def test_each_phone_numbers_sessions_have_their_own_bucket():
    view = make_view(SessionTokenAuthentication)
    first = session_bearer("+27831234567")

    assert [call(view, first) for _ in range(3)] == [200, 200, 429]
    # Before, every session shared the bucket keyed on pk None, so this was throttled too
    assert call(view, session_bearer("+27831234568")) == 200
    # A new session for the same number doesn't get a fresh quota
    assert call(view, session_bearer("+27831234567")) == 429


@pytest.mark.django_db
def test_session_bucket_does_not_store_the_phone_number():
    call(make_view(SessionTokenAuthentication), session_bearer("+27831234567"))

    keys = list(caches["throttle"]._cache)
    assert any("throttle_user_session_phone:" in key for key in keys)
    assert not any("27831234567" in key for key in keys)


def test_fake_user_without_an_ident_is_keyed_per_client():
    class OtherFakeUser(AnonymousUser):
        @property
        def is_authenticated(self):
            return True

    def key_for(address):
        request = APIRequestFactory().get("/", REMOTE_ADDR=address)
        request.user = OtherFakeUser()
        return ServiceAwareUserRateThrottle().get_cache_key(request, None)

    assert key_for("10.0.0.1") == "throttle_user_unidentified:10.0.0.1"
    assert key_for("10.0.0.2") != key_for("10.0.0.1")
