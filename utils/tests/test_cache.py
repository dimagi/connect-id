from unittest import mock

import pytest
from redis.exceptions import ConnectionError

from utils.cache import FailSoftRedisCache


@pytest.fixture
def cache():
    """A cache whose Redis client fails every call."""
    cache = FailSoftRedisCache("redis://127.0.0.1:1/0", {"KEY_PREFIX": "test"})
    client = mock.Mock()
    for method in ["get", "add", "set", "delete", "get_many", "set_many", "delete_many", "has_key"]:
        getattr(client, method).side_effect = ConnectionError("down")
    cache._cache = client
    return cache


def test_reads_miss_and_writes_are_skipped_while_redis_is_down(cache):
    assert cache.get("k") is None
    assert cache.get("k", "fallback") == "fallback"
    assert cache.add("k", 1) is False
    assert cache.set("k", 1) is None
    assert cache.delete("k") is False
    assert cache.get_many(["a", "b"]) == {}
    assert cache.set_many({"a": 1, "b": 2}) == ["a", "b"]
    assert cache.delete_many(["a"]) is None
    assert cache.has_key("k") is False


def test_redis_is_not_retried_straight_after_a_failure(cache, caplog):
    cache.get("a")
    cache.get("b")
    cache.set("c", 1)

    assert cache._cache.get.call_count == 1
    assert cache._cache.set.call_count == 0
    assert caplog.text.count("Cache test unavailable") == 1


def test_redis_is_retried_after_the_pause(cache):
    with mock.patch("utils.cache.time.monotonic", return_value=1000.0):
        cache.get("a")
    with mock.patch("utils.cache.time.monotonic", return_value=1031.0):
        cache.get("b")

    assert cache._cache.get.call_count == 2


def test_a_working_redis_is_used():
    cache = FailSoftRedisCache("redis://127.0.0.1:1/0", {"KEY_PREFIX": "test"})
    cache._cache = mock.Mock()
    cache._cache.get.return_value = 5

    assert cache.get("k") == 5
