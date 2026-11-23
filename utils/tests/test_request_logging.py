import logging

import pytest

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
    assert record.getMessage().startswith("request method=POST route=/users/heartbeat ")


@pytest.mark.django_db
def test_logs_the_route_pattern_not_the_path_or_query(api_client, caplog):
    api_client.get("/users/accept_credential/secret-invite-id?token=abc")

    [record] = _request_logs(caplog)
    assert record.request_log["route"] == "/users/accept_credential/<slug:invite_id>"
    assert record.request_log["user_id"] is None
    assert "secret-invite-id" not in record.getMessage()
    assert "abc" not in record.getMessage()


@pytest.mark.django_db
def test_logs_the_path_of_an_unmatched_request(api_client, caplog):
    api_client.get("/no/such/page?token=abc")

    [record] = _request_logs(caplog)
    assert record.request_log["route"] == "/no/such/page"
    assert record.request_log["status"] == 404


def test_skips_the_liveness_probe(client, caplog):
    client.get("/up")

    assert _request_logs(caplog) == []
