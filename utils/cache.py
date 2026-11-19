"""A Redis cache that treats an unreachable Redis as an empty cache, for caches that only save work."""

import logging
import time
from functools import wraps

from django.core.cache.backends.redis import RedisCache
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

# After a failure, Redis isn't tried again in this process for this long, so an outage costs one
# connection timeout per process per period instead of one per call.
RETRY_AFTER_SECONDS = 30


def _fail_soft(fallback):
    def decorator(method):
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            if time.monotonic() < self._down_until:
                return fallback(*args, **kwargs)
            try:
                return method(self, *args, **kwargs)
            except RedisError:
                self._down_until = time.monotonic() + RETRY_AFTER_SECONDS
                logger.warning(
                    "Cache %s unavailable; skipping it for %ss", self._alias_hint, RETRY_AFTER_SECONDS, exc_info=True
                )
                return fallback(*args, **kwargs)

        return wrapper

    return decorator


def _default(key, default=None, version=None):
    return default


class FailSoftRedisCache(RedisCache):
    """A RedisCache whose reads miss and whose writes are skipped while Redis can't be reached.

    Only for caches in front of another source of truth (e.g. the database), where a miss costs time, not
    correctness.
    """

    def __init__(self, server, params):
        super().__init__(server, params)
        self._down_until = 0.0
        self._alias_hint = params.get("KEY_PREFIX") or "redis"

    get = _fail_soft(_default)(RedisCache.get)
    add = _fail_soft(lambda *a, **kw: False)(RedisCache.add)
    set = _fail_soft(lambda *a, **kw: None)(RedisCache.set)
    delete = _fail_soft(lambda *a, **kw: False)(RedisCache.delete)
    get_many = _fail_soft(lambda *a, **kw: {})(RedisCache.get_many)
    set_many = _fail_soft(lambda data, *a, **kw: list(data))(RedisCache.set_many)
    delete_many = _fail_soft(lambda *a, **kw: None)(RedisCache.delete_many)
    has_key = _fail_soft(lambda *a, **kw: False)(RedisCache.has_key)
