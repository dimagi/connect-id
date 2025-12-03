import logging
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlencode

import requests
from celery import shared_task
from django.conf import settings

logger = logging.getLogger(__name__)


@dataclass
class GATrackingInfo:
    client_id: str
    session_id: str

    @classmethod
    def from_request(cls, request):
        client_id = _get_firebase_client_id(request)
        session_id = _get_firebase_session_id(request)
        return cls(client_id=client_id, session_id=session_id)


@dataclass
class Event:
    name: str
    params: dict[str, Any]


def send_event_to_ga(request, event: Event):
    send_bulk_events_to_ga(request, [event])


def send_bulk_events_to_ga(request, events: list[Event]):
    if not settings.FIREBASE_APP_ID or not settings.FIREBASE_APP_ID.strip():
        logger.info("Please specify FIREBASE_APP_ID environment variable.")
        return

    if not settings.GA_API_SECRET or not settings.GA_API_SECRET.strip():
        logger.info("Please specify GA_API_SECRET environment variable.")
        return

    tracking_info = GATrackingInfo.from_request(request)
    if not tracking_info.client_id or not tracking_info.session_id:
        logger.info("Missing required Firebase headers from request.")
        return

    enriched_events = []
    for event in events:
        enriched_params = {
            **event.params,
            "session_id": tracking_info.session_id,
            # This is needed for tracking to work properly.
            "engagement_time_msec": 100,
        }
        enriched_events.append(Event(name=event.name, params=enriched_params))
    send_ga_event.delay(tracking_info.client_id, _serialize_events(enriched_events))


@shared_task(name="send_ga_event")
def send_ga_event(client_id: str, events: list[Event]):
    base_url = "https://www.google-analytics.com/mp/collect"
    params = {"firebase_app_id": settings.FIREBASE_APP_ID, "api_secret": settings.GA_API_SECRET}
    url = f"{base_url}?{urlencode(params)}"
    payload = {"app_instance_id": client_id, "events": events}

    response = requests.post(url, json=payload, timeout=10)
    response.raise_for_status()


def _serialize_events(events: list[Event]):
    return [asdict(event) for event in events]


def _get_firebase_client_id(request):
    return request.headers.get("X-Firebase-Instance-ID")


def _get_firebase_session_id(request):
    return request.headers.get("X-Firebase-Session-ID")
