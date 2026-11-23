import logging

import pytest
from django.http import HttpResponse

from utils.middleware import RequestLoggingMiddleware

LOGGER = "connectid.requests"


def _request_logs(caplog):
    return [r for r in caplog.records if r.name == LOGGER]


@pytest.fixture(autouse=True)
def capture_requests(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER)


@pytest.mark.django_db
def test_logs_an_authenticated_request(auth_device, user, caplog):
    response = auth_device.post("/users/heartbeat", {})

    [record] = _request_logs(caplog)
    fields = record.request_log
    assert fields["method"] == "POST"
    assert fields["route"] == "/users/heartbeat"
    assert fields["status"] == response.status_code
    assert fields["user_id"] == user.pk
    assert isinstance(fields["duration_ms"], int)
    assert record.getMessage().startswith("request method=POST route=/users/heartbeat query= ")


@pytest.mark.django_db
def test_logs_the_route_pattern_not_the_path_or_query(api_client, caplog):
    api_client.get("/users/accept_credential/secret-invite-id?token=abc")

    [record] = _request_logs(caplog)
    assert record.request_log["route"] == "/users/accept_credential/<slug:invite_id>"
    assert record.request_log["user_id"] is None
    assert "secret-invite-id" not in record.getMessage()
    assert "abc" not in record.getMessage()


@pytest.mark.django_db
def test_logs_an_unmatched_request_without_its_path(api_client, caplog):
    # accept_credential has no trailing slash, so this near miss matches no route.
    api_client.get("/users/accept_credential/secret-invite-id/")

    [record] = _request_logs(caplog)
    assert record.request_log["route"] == "<unresolved>"
    assert record.request_log["status"] == 404
    assert "secret-invite-id" not in record.getMessage()
    assert "secret-invite-id" not in str(record.request_log)


@pytest.mark.django_db
def test_an_encoded_newline_in_the_path_cannot_forge_a_log_line(api_client, caplog):
    api_client.get("/nope%0AINFO%20forged%20line")

    [record] = _request_logs(caplog)
    assert "\n" not in record.getMessage()
    assert "forged" not in record.getMessage()


@pytest.mark.django_db
def test_logs_query_parameter_names_but_not_values(api_client, caplog):
    api_client.get("/users/accept_credential/abc?phone_number=%2B15555550123&generation=2&token=secret")

    [record] = _request_logs(caplog)
    assert record.request_log["query"] == "phone_number,generation,token"
    assert "15555550123" not in record.getMessage()
    assert "secret" not in record.getMessage()


@pytest.mark.django_db
def test_logs_an_empty_query_when_there_is_none(auth_device, caplog):
    auth_device.post("/users/heartbeat", {})

    [record] = _request_logs(caplog)
    assert record.request_log["query"] == ""


@pytest.mark.django_db
def test_masks_query_parameter_names_that_are_not_identifiers(api_client, caplog):
    api_client.get("/users/accept_credential/abc?ok=1&bad%0Aname=1&a%20b=1")

    [record] = _request_logs(caplog)
    assert record.request_log["query"] == "ok,?,?"
    assert "\n" not in record.getMessage()


@pytest.mark.django_db
def test_keeps_only_the_first_query_parameter_names(api_client, caplog):
    params = "&".join(f"p{i}=1" for i in range(30))
    api_client.get(f"/users/accept_credential/abc?{params}")

    [record] = _request_logs(caplog)
    assert record.request_log["query"] == ",".join(f"p{i}" for i in range(20))


def test_more_query_parameters_than_django_parses_do_not_change_the_response(rf, caplog):
    # Past DATA_UPLOAD_MAX_NUMBER_FIELDS, reading request.GET raises. DRF views read it anyway, but a
    # plain view that doesn't must not get a 400 because the middleware read it.
    params = "&".join(f"p{i}=1" for i in range(1001))
    request = rf.get(f"/plain?{params}")
    request.resolver_match = None
    middleware = RequestLoggingMiddleware(lambda request: HttpResponse("ok"))

    response = middleware(request)

    assert response.status_code == 200
    [record] = _request_logs(caplog)
    assert record.request_log["query"] == ",".join(f"p{i}" for i in range(20))


@pytest.mark.django_db
def test_logs_a_repeated_query_parameter_once(api_client, caplog):
    api_client.get("/users/accept_credential/abc?id=1&id=2&x=3")

    [record] = _request_logs(caplog)
    assert record.request_log["query"] == "id,x"


@pytest.mark.django_db
def test_logs_nothing_when_the_logger_is_turned_off(api_client, caplog):
    caplog.set_level(logging.WARNING, logger=LOGGER)

    api_client.get("/users/accept_credential/abc")

    assert _request_logs(caplog) == []


def test_skips_the_liveness_probe(client, caplog):
    client.get("/up")

    assert _request_logs(caplog) == []
