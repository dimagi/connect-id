from unittest import mock

from utils.rate_limit import Limit, hit


def test_allows_events_up_to_the_limit():
    limits = [Limit(2, 60)]
    assert hit("key", limits) is None
    assert hit("key", limits) is None

    exceeded = hit("key", limits)

    assert exceeded.limit == Limit(2, 60)
    assert exceeded.count == 3
    assert exceeded.is_first
    assert 0 < exceeded.retry_after_seconds <= 61
    assert not hit("key", limits).is_first


def test_keys_are_counted_separately():
    limits = [Limit(1, 60)]
    assert hit("one", limits) is None
    assert hit("two", limits) is None


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
