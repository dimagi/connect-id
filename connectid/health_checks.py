"""Health checks served at /status/ (see connectid.views.HealthCheck).

Each subset is the list of checks one /status/ URL runs:

- ``general`` (``/status/``): the web process's own dependencies, the database and the Redis
  broker. It leaves out Celery so that the web tier is not reported down because workers are.
- ``celery`` (``/status/celery/``): at least one Celery worker answers a ping and every
  configured queue has a worker consuming it.

A check is a ``health_check`` check path, optionally as a ``(path, kwargs)`` tuple, or a subclass
of ``health_check.base.HealthCheck`` that raises ``ServiceUnavailable`` from ``run()``.
"""

import dataclasses
import datetime

import celery
from celery.app import app_or_default
from django.conf import settings
from health_check.contrib.celery import Ping
from redis.asyncio import Redis as RedisClient

# Celery's broadcast ping reports a slow reply the same as no reply, so leave headroom for a busy
# broker, for example while a deploy restarts the worker.
CELERY_PING_TIMEOUT = datetime.timedelta(seconds=3)


@dataclasses.dataclass
class CeleryPing(Ping):
    """The library's Celery check, without the app's memory address in its name on the status page."""

    app: celery.Celery = dataclasses.field(default_factory=app_or_default, repr=False)


def _broker_client():
    return RedisClient.from_url(settings.CELERY_BROKER_URL)


def _check_subsets():
    return {
        "general": [
            "health_check.checks.Database",
            ("health_check.contrib.redis.Redis", {"client_factory": _broker_client}),
        ],
        "celery": [
            (CeleryPing, {"timeout": CELERY_PING_TIMEOUT}),
        ],
    }


CHECK_SUBSETS = _check_subsets()
