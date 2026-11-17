import base64
import logging

import pytest
from django.http import HttpResponse, JsonResponse
from django.test import RequestFactory
from django.urls import reverse
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.response import Response

from users.const import ErrorCodes
from utils.middleware import Log401ErrorsMiddleware


def _basic(credentials):
    return "Basic " + base64.b64encode(credentials.encode()).decode()


def _run(response, authorization=None):
    headers = {"HTTP_AUTHORIZATION": authorization} if authorization else {}
    request = RequestFactory().post("/users/some_view", **headers)
    return Log401ErrorsMiddleware(lambda request: response)(request)


def _records(caplog):
    return [record for record in caplog.records if record.getMessage().startswith("auth_401")]


@pytest.mark.parametrize(
    "response",
    [
        JsonResponse({"error_code": ErrorCodes.INCORRECT_OTP, "attempts_left": 2}, status=401),
        JsonResponse({"error": "OTP token is incorrect"}, status=401),
        Response(AuthenticationFailed({"error_code": ErrorCodes.TOKEN_EXPIRED}).detail, status=401),
        Response({"detail": NotAuthenticated().detail}, status=401),
    ],
)
def test_expected_401s_are_logged_at_info(caplog, response):
    with caplog.at_level(logging.INFO, logger="utils.middleware"):
        _run(response)

    [record] = _records(caplog)
    assert record.levelno == logging.INFO


@pytest.mark.parametrize(
    "response, reason",
    [
        (JsonResponse({"error_code": ErrorCodes.INVALID_SECRET_KEY}, status=401), ErrorCodes.INVALID_SECRET_KEY),
        (Response({"detail": AuthenticationFailed().detail}, status=401), "authentication_failed"),
        (HttpResponse(status=401), "unknown"),
    ],
)
def test_unexpected_401s_are_logged_at_error_with_their_reason(caplog, response, reason):
    with caplog.at_level(logging.INFO, logger="utils.middleware"):
        _run(response, authorization="Bearer abc")

    [record] = _records(caplog)
    assert record.levelno == logging.ERROR
    assert record.getMessage() == f"auth_401 reason={reason} path=/users/some_view scheme=Bearer"
    assert record.auth_401 == {"reason": reason, "path": "/users/some_view", "scheme": "Bearer"}


@pytest.mark.parametrize(
    "authorization, scheme",
    [
        (None, "none"),
        (_basic("user:pass"), "Basic"),
        (_basic("no-colon"), "Basic(malformed)"),
        ("Basic !!!notbase64", "Basic(malformed)"),
        ("Basic", "Basic(malformed)"),
        ("Something-odd value", "other"),
    ],
)
def test_auth_scheme_is_recorded(caplog, authorization, scheme):
    with caplog.at_level(logging.INFO, logger="utils.middleware"):
        _run(HttpResponse(status=401), authorization=authorization)

    [record] = _records(caplog)
    assert record.auth_401["scheme"] == scheme


def test_other_statuses_are_not_logged(caplog):
    with caplog.at_level(logging.INFO, logger="utils.middleware"):
        _run(JsonResponse({"error_code": ErrorCodes.INVALID_DATA}, status=400))

    assert _records(caplog) == []


@pytest.mark.django_db
def test_wrong_device_credentials_are_reported(caplog, user, api_client):
    api_client.credentials(HTTP_AUTHORIZATION=_basic(f"{user.username}:wrong"))

    with caplog.at_level(logging.INFO, logger="utils.middleware"):
        response = api_client.get(reverse("messaging:retrieve_notifications"))

    assert response.status_code == 401
    [record] = _records(caplog)
    assert record.levelno == logging.ERROR
    assert record.auth_401 == {
        "reason": "authentication_failed",
        "path": "/messaging/retrieve_notifications/",
        "scheme": "Basic",
    }


@pytest.mark.django_db
def test_missing_credentials_are_not_reported(caplog, api_client):
    with caplog.at_level(logging.INFO, logger="utils.middleware"):
        response = api_client.get(reverse("messaging:retrieve_notifications"))

    assert response.status_code == 401
    [record] = _records(caplog)
    assert record.levelno == logging.INFO
    assert record.auth_401["reason"] == "not_authenticated"
