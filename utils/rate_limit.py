"""Fixed-window counters kept in the shared "rate_limit" cache, so limits hold across processes and hosts."""

import logging
import time
from dataclasses import dataclass

from django.core.cache import caches

logger = logging.getLogger(__name__)

CACHE_ALIAS = "rate_limit"


@dataclass(frozen=True)
class Limit:
    max_count: int
    window_seconds: int


@dataclass(frozen=True)
class Exceeded:
    limit: Limit
    count: int
    retry_after_seconds: int

    @property
    def is_first(self):
        """True for the one event that went over the limit, so callers can report a limit once per window."""
        return self.count == self.limit.max_count + 1


def hit(key: str, limits: list[Limit]) -> Exceeded | None:
    """Count one event under `key` against each limit.

    Returns the exceeded limit with the longest wait, or None if every limit still has room. If the
    cache cannot be reached, the event is allowed and the failure is logged as an error.
    """
    now = time.time()
    exceeded = []
    try:
        for limit in limits:
            window = int(now // limit.window_seconds)
            count = _increment(f"{key}:{limit.window_seconds}:{window}", limit.window_seconds)
            if count > limit.max_count:
                retry_after = int((window + 1) * limit.window_seconds - now) + 1
                exceeded.append(Exceeded(limit, count, retry_after))
    except Exception:
        logger.exception("Rate limit cache unavailable; allowing %s", key)
        return None
    return max(exceeded, key=lambda e: e.retry_after_seconds, default=None)


def _increment(cache_key, timeout):
    cache = caches[CACHE_ALIAS]
    cache.add(cache_key, 0, timeout=timeout)
    try:
        return cache.incr(cache_key)
    except ValueError:
        # The key expired between add() and incr().
        cache.set(cache_key, 1, timeout=timeout)
        return 1
