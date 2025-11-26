import logging
import uuid
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlencode

import requests
from celery import shared_task
from django.conf import settings
from django.utils.timezone import now

logger = logging.getLogger(__name__)


@dataclass
class Event:
    name: str
    params: dict[str, Any]


def send_event_to_ga(request, event: Event):
    send_bulk_events_to_ga(request, [event])


def send_bulk_events_to_ga(request, events: list[Event]):
    if not settings.GA_MEASUREMENT_ID:
        logger.info("Please specify GA_MEASUREMENT_ID environment variable.")
        return

    if not settings.GA_API_SECRET:
        logger.info("Please specify GA_API_SECRET environment variable.")
        return

    client_id = _get_ga_client_id(request)
    session_id = _get_ga_session_id(request)
    enriched_events = []
    for event in events:
        enriched_params = {
            **event.params,
            "session_id": session_id,
            # This is needed for tracking to work properly.
            "engagement_time_msec": 100,
        }
        enriched_events.append(Event(name=event.name, params=enriched_params))
    send_ga_event.delay(client_id, _serialize_events(enriched_events))


@shared_task(name="send_ga_event")
def send_ga_event(client_id: str, events: list[Event]):
    base_url = "https://www.google-analytics.com/mp/collect"
    params = {"measurement_id": settings.GA_MEASUREMENT_ID, "api_secret": settings.GA_API_SECRET}
    url = f"{base_url}?{urlencode(params)}"
    payload = {"client_id": client_id, "events": events}

    response = requests.post(url, json=payload, timeout=10)
    response.raise_for_status()


def _serialize_events(events: list[Event]):
    return [asdict(event) for event in events]


def _get_ga_client_id(request):
    if hasattr(request, "user") and request.user and request.user.id:
        return f"personalid-user-{request.user.id}"
    return f"personalid-anon-{uuid.uuid4()}"


def _get_ga_session_id(request):
    try:
        return str(request.user.get_session_timestamp().timestamp())
    except AttributeError:
        return str(now().timestamp())
