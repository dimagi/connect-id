from unittest import mock

import pytest

from utils.rate_limit import Limit, hit, log_event, release


@pytest.fixture
def frozen_time():
    """Fix the clock mid-window, so the counts don't move to a new window during a test."""
    with mock.patch("utils.rate_limit.time.time", return_value=1000.0):
        yield


@pytest.mark.usefixtures("frozen_time")
def test_allows_events_up_to_the_limit():
    limits = [Limit(2, 60)]
    assert hit("key", limits) is None
    assert hit("key", limits) is None

    exceeded = hit("key", limits)

    assert exceeded.limit == Limit(2, 60)
    assert exceeded.count == 3
    assert exceeded.is_first
    assert exceeded.retry_after_seconds == 21
    assert not hit("key", limits).is_first


def test_keys_are_counted_separately():
    limits = [Limit(1, 60)]
    assert hit("one", limits) is None
    assert hit("two", limits) is None


@pytest.mark.usefixtures("frozen_time")
def test_reports_the_exceeded_limit_with_the_longest_wait():
    hour, day = Limit(1, 60 * 60), Limit(1, 24 * 60 * 60)
    hit("key", [hour, day])

    assert hit("key", [hour, day]).limit == day


def test_a_new_window_starts_from_zero():
    limits = [Limit(1, 60)]
    with mock.patch("utils.rate_limit.time.time", return_value=1000.0):
        hit("key", limits)
        assert hit("key", limits) is not None
    with mock.patch("utils.rate_limit.time.time", return_value=1060.0):
        assert hit("key", limits) is None


def test_allows_events_when_the_cache_is_unavailable(caplog):
    with mock.patch("utils.rate_limit.caches") as caches:
        caches.__getitem__.return_value.add.side_effect = ConnectionError("redis down")
        assert hit("sms:number:+265991234567", [Limit(0, 60)]) is None

    assert "Rate limit cache unavailable; allowing sms:number" in caplog.text
    assert "+265991234567" not in caplog.text


def test_a_key_that_expires_between_calls_starts_again():
    cache = mock.Mock()
    cache.add.side_effect = [False, True]
    cache.incr.side_effect = ValueError("key expired")
    with mock.patch("utils.rate_limit.caches") as caches:
        caches.__getitem__.return_value = cache
        assert hit("key", [Limit(1, 60)]) is None

    assert cache.add.call_count == 2


@pytest.mark.usefixtures("frozen_time")
def test_release_takes_back_a_hit():
    limits = [Limit(1, 60), Limit(1, 60 * 60)]
    hit("key", limits)
    release("key", limits)

    assert hit("key", limits) is None


def test_release_without_a_hit_does_nothing():
    release("key", [Limit(1, 60)])

    assert hit("key", [Limit(1, 60)]) is None


def _events(caplog):
    return [(r.levelname, r.getMessage()) for r in caplog.records if r.name == "utils.rate_limit"]


@pytest.mark.usefixtures("frozen_time")
def test_each_rejection_is_logged_with_its_fields(caplog):
    limits = [Limit(1, 60)]
    fields = {"scope": "sms", "kind": "country", "country_code": 265}
    hit("key", limits, log_fields=fields)
    assert _events(caplog) == []

    hit("key", limits, log_fields=fields)
    hit("key", limits, log_fields=fields)

    message = "rate_limit_blocked scope=sms kind=country country_code=265 window_seconds=60 max_count=1"
    assert _events(caplog) == [
        ("WARNING", f"{message} count=2 retry_after_seconds=21"),
        ("WARNING", f"{message} count=3 retry_after_seconds=21"),
    ]
    assert caplog.records[0].rate_limit == {
        "event": "rate_limit_blocked",
        **fields,
        "window_seconds": 60,
        "max_count": 1,
        "count": 2,
        "retry_after_seconds": 21,
    }


def test_without_log_fields_only_the_scope_of_the_key_is_logged(caplog):
    hit("sms:number:+265991234567", [Limit(0, 60)])

    assert "rate_limit_blocked key=sms:number " in caplog.text
    assert "+265991234567" not in caplog.text


@pytest.mark.usefixtures("frozen_time")
def test_reaching_warn_at_is_logged_once(caplog):
    limits = [Limit(3, 60, warn_at=2)]
    for _ in range(3):
        hit("otp:user:1", limits)

    message = "rate_limit_approaching key=otp:user window_seconds=60 max_count=3 count=2"
    assert _events(caplog) == [("WARNING", message)]


@pytest.mark.usefixtures("frozen_time")
def test_reported_limits_raise_errors_once_per_window(caplog):
    limits = [Limit(2, 60, warn_at=1)]
    for _ in range(4):
        hit("key", limits, log_fields={"scope": "test"}, report=True)

    errors = [message for level, message in _events(caplog) if level == "ERROR"]
    assert errors == [
        "rate_limit_approaching scope=test window_seconds=60 max_count=2 count=1",
        "rate_limit_reached scope=test window_seconds=60 max_count=2",
    ]


def test_log_event_tags_the_sentry_event():
    with mock.patch("utils.rate_limit.sentry_sdk.new_scope") as new_scope:
        log_event("rate_limit_blocked", {"scope": "otp", "user_id": 7})

    scope = new_scope.return_value.__enter__.return_value
    scope.set_tag.assert_has_calls(
        [
            mock.call("rate_limit.event", "rate_limit_blocked"),
            mock.call("rate_limit.scope", "otp"),
            mock.call("rate_limit.user_id", 7),
        ]
    )
