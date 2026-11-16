"""Fixed-window counters kept in the shared "rate_limit" cache, so limits hold across processes and hosts.

Rate limit events are logged as one line each, `<event> key=value ...`, so they can be searched and counted
in the logs (see docs/rate-limits.md):

- `rate_limit_blocked`: an event was rejected. Logged for every rejection.
- `rate_limit_approaching`: a count reached a limit's `warn_at`. Logged once per window.
- `rate_limit_reached`: the first rejection in a window, for limits that `report` it. Logged once per window.
- `rate_limit_suppressed`: a rejection the caller didn't pass on, so the user wasn't told to wait.
"""

import logging
import time
from dataclasses import dataclass

import sentry_sdk
from django.core.cache import caches

logger = logging.getLogger(__name__)

CACHE_ALIAS = "rate_limit"

BLOCKED = "rate_limit_blocked"
APPROACHING = "rate_limit_approaching"
REACHED = "rate_limit_reached"
SUPPRESSED = "rate_limit_suppressed"


@dataclass(frozen=True)
class Limit:
    max_count: int
    window_seconds: int
    # The count at which `rate_limit_approaching` is logged, if any.
    warn_at: int | None = None


@dataclass(frozen=True)
class Exceeded:
    limit: Limit
    count: int
    retry_after_seconds: int

    @property
    def is_first(self):
        """True for the one event that went over the limit, so callers can report a limit once per window."""
        return self.count == self.limit.max_count + 1


def hit(key: str, limits: list[Limit], log_fields: dict | None = None, report: bool = False) -> Exceeded | None:
    """Count one event under `key` against each limit.

    Returns the exceeded limit with the longest wait, or None if every limit still has room. If the
    cache cannot be reached, the event is allowed and the failure is logged as an error.

    Rejections and limits approached are logged with `log_fields`, which say what was limited and must
    not hold a full phone number. With `report`, the approaching and reached events are errors, which
    reach Sentry: use it for limits that block many people at once.
    """
    now = time.time()
    exceeded = []
    approaching = []
    try:
        for limit in limits:
            window = int(now // limit.window_seconds)
            count = _increment(f"{key}:{limit.window_seconds}:{window}", limit.window_seconds)
            if count == limit.warn_at:
                approaching.append((limit, count))
            if count > limit.max_count:
                retry_after = int((window + 1) * limit.window_seconds - now) + 1
                exceeded.append(Exceeded(limit, count, retry_after))
    except Exception:
        # The key can end in a phone number, so log only its scope.
        logger.exception("Rate limit cache unavailable; allowing %s", _scope(key))
        return None

    fields = log_fields or {"key": _scope(key)}
    level = logging.ERROR if report else logging.WARNING
    for limit, count in approaching:
        log_event(APPROACHING, {**fields, **_limit_fields(limit), "count": count}, level)
    for e in exceeded:
        if report and e.is_first:
            log_event(REACHED, {**fields, **_limit_fields(e.limit)}, level)
    worst = max(exceeded, key=lambda e: e.retry_after_seconds, default=None)
    if worst:
        log_event(
            BLOCKED,
            {
                **fields,
                **_limit_fields(worst.limit),
                "count": worst.count,
                "retry_after_seconds": worst.retry_after_seconds,
            },
        )
    return worst


def log_event(event: str, fields: dict, level: int = logging.WARNING):
    """Log a rate limit event as `<event> key=value ...`. The fields are also Sentry tags, for errors.

    The message is built here rather than from a format string, so Sentry groups errors by their fields:
    keep the fields of an error the same across a window (no retry times) so it is one issue per window.
    """
    message = " ".join([event, *(f"{name}={value}" for name, value in fields.items())])
    with sentry_sdk.new_scope() as scope:
        scope.set_tag("rate_limit.event", event)
        for name, value in fields.items():
            scope.set_tag(f"rate_limit.{name}", value)
        logger.log(level, message, extra={"rate_limit": {"event": event, **fields}})


def _limit_fields(limit: Limit) -> dict:
    return {"window_seconds": limit.window_seconds, "max_count": limit.max_count}


def _scope(key: str) -> str:
    return key.rpartition(":")[0]


def release(key: str, limits: list[Limit]):
    """Take back one hit(), for an event that was rejected or then didn't happen.

    If a window has ended in between, the count in the new window is reduced instead. That is at most
    one event, once per window, and it errs on the side of allowing.
    """
    now = time.time()
    try:
        _decrement([f"{key}:{limit.window_seconds}:{int(now // limit.window_seconds)}" for limit in limits])
    except Exception:
        logger.exception("Rate limit cache unavailable; could not release %s", key.rpartition(":")[0])


def _decrement(cache_keys):
    cache = caches[CACHE_ALIAS]
    for cache_key in cache_keys:
        try:
            cache.decr(cache_key)
        except ValueError:
            pass  # The window has ended, so there is nothing to take off.


def _increment(cache_key, timeout):
    """Add 1 to the key's count. add() and incr() are each atomic, so concurrent callers never share a count."""
    cache = caches[CACHE_ALIAS]
    if cache.add(cache_key, 1, timeout=timeout):
        return 1
    try:
        return cache.incr(cache_key)
    except ValueError:
        # The key expired after add() found it: start it again, unless another caller just did.
        return 1 if cache.add(cache_key, 1, timeout=timeout) else cache.incr(cache_key)
