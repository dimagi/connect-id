from unittest import mock

import pytest
from django.urls import reverse
from redis.exceptions import ConnectionError as RedisConnectionError

from connectid import settings as django_settings_module
from connectid.celery_app import app as celery_app
from connectid.health_checks import RedisClient


@pytest.fixture
def redis_up():
    with mock.patch.object(RedisClient, "ping", new_callable=mock.AsyncMock, return_value=True) as ping:
        yield ping


@pytest.fixture
def redis_down():
    with mock.patch.object(RedisClient, "ping", new_callable=mock.AsyncMock, side_effect=RedisConnectionError()):
        yield


@pytest.fixture
def celery_workers():
    """A worker that answers the ping and consumes the default queue, unless a test changes it."""
    state = {
        "ping": [{"celery@worker": {"ok": "pong"}}],
        "active_queues": {"celery@worker": [{"name": "celery"}]},
    }
    with (
        mock.patch.object(celery_app.control, "ping", side_effect=lambda **kw: state["ping"]),
        mock.patch.object(celery_app.control, "inspect") as inspect,
    ):
        inspect.return_value.active_queues.side_effect = lambda: state["active_queues"]
        yield state


class TestUp:
    def test_ok_without_database_or_auth(self, client, settings):
        settings.HEALTH_CHECK_TOKENS = ["secret"]
        response = client.get("/up")
        assert response.status_code == 200
        assert response.content == b"OK"
        assert "no-cache" in response["Cache-Control"]

    def test_trailing_slash(self, client):
        assert client.get("/up/").status_code == 200

    def test_reverse(self):
        assert reverse("up") == "/up"


@pytest.mark.django_db(transaction=True)
class TestStatusGeneral:
    def test_healthy(self, client, redis_up):
        response = client.get("/status/", HTTP_ACCEPT="application/json")
        assert response.status_code == 200
        body = response.json()
        assert set(body.values()) == {"OK"}
        assert any(key.startswith("Database") for key in body)
        assert any(key.startswith("Redis") for key in body)
        redis_up.assert_awaited_once()

    def test_redis_down(self, client, redis_down):
        response = client.get("/status/", HTTP_ACCEPT="application/json")
        assert response.status_code == 500
        redis_result = next(value for key, value in response.json().items() if key.startswith("Redis"))
        assert "Unavailable" in redis_result

    def test_does_not_check_celery(self, client, redis_up):
        with mock.patch.object(celery_app.control, "ping") as ping:
            assert client.get("/status/").status_code == 200
        ping.assert_not_called()

    def test_plain_text(self, client, redis_up):
        response = client.get("/status/?format=text")
        assert response.status_code == 200
        assert response["Content-Type"].startswith("text/plain")


class TestStatusCelery:
    def test_healthy(self, client, celery_workers):
        response = client.get("/status/celery/", HTTP_ACCEPT="application/json")
        assert response.status_code == 200
        assert response.json() == {"CeleryPing()": "OK"}

    def test_no_workers(self, client, celery_workers):
        celery_workers["ping"] = []
        response = client.get("/status/celery/", HTTP_ACCEPT="application/json")
        assert response.status_code == 500
        assert list(response.json().values()) == ["Unavailable: Celery workers unavailable"]

    def test_queue_without_worker(self, client, celery_workers):
        celery_workers["active_queues"] = {"celery@worker": [{"name": "other"}]}
        response = client.get("/status/celery/", HTTP_ACCEPT="application/json")
        assert response.status_code == 500
        assert list(response.json().values()) == ["Unavailable: No worker for Celery task queue celery"]

    def test_broker_unreachable(self, client):
        with mock.patch.object(celery_app.control, "ping", side_effect=OSError):
            response = client.get("/status/celery/", HTTP_ACCEPT="application/json")
        assert response.status_code == 500
        assert list(response.json().values()) == ["Unavailable: IOError"]


class TestStatusAccess:
    def test_unknown_subset_404(self, client):
        assert client.get("/status/nope/").status_code == 404

    @pytest.mark.parametrize("query", ["", "?token=wrong", "?token="])
    def test_bad_token_404(self, client, settings, query):
        settings.HEALTH_CHECK_TOKENS = ["secret", "other"]
        assert client.get(f"/status/celery/{query}").status_code == 404

    @pytest.mark.parametrize("token", ["secret", "other"])
    def test_valid_token(self, client, settings, celery_workers, token):
        settings.HEALTH_CHECK_TOKENS = ["secret", "other"]
        assert client.get(f"/status/celery/?token={token}").status_code == 200

    def test_open_when_no_tokens(self, client, settings, celery_workers):
        settings.HEALTH_CHECK_TOKENS = []
        assert client.get("/status/celery/").status_code == 200

    def test_not_cached(self, client, celery_workers):
        assert "no-cache" in client.get("/status/celery/")["Cache-Control"]


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/up", 0),
        ("/up/", 0),
        ("/status/", 0),
        ("/status/celery/", 0),
        ("/users/", 0.5),
        ("/upload", 0.5),
    ],
)
def test_traces_sampler_skips_health_checks(monkeypatch, path, expected):
    monkeypatch.setattr(django_settings_module, "SENTRY_TRACES_SAMPLE_RATE", 0.5)
    assert django_settings_module.traces_sampler({"wsgi_environ": {"PATH_INFO": path}}) == expected


def test_traces_sampler_follows_parent(monkeypatch):
    monkeypatch.setattr(django_settings_module, "SENTRY_TRACES_SAMPLE_RATE", 0.5)
    assert django_settings_module.traces_sampler({"parent_sampled": True}) == 1.0
    assert django_settings_module.traces_sampler({"parent_sampled": False}) == 0.0
    assert django_settings_module.traces_sampler({}) == 0.5
