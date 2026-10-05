"""Pins what each consumer of a message receives, as literal values.

Apps in the field parse these, and some read messages straight from the push, so a plain
message's output must not change. Rich fields may appear only in the retrieve_notifications sync.
"""

import json
import re
import uuid
from datetime import UTC, datetime
from unittest import mock

import pytest
from django.urls import reverse
from firebase_admin import messaging

from messaging.factories import ChannelFactory, MessageAttachmentFactory, MessageFactory, ServerFactory
from messaging.models import MessageDirection, Notification
from messaging.serializers import MessageSerializer
from messaging.tasks import send_bulk_notification_task
from users.factories import FCMDeviceFactory, ServerKeysFactory

pytestmark = pytest.mark.django_db

CHANNEL_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
MESSAGE_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
TIMESTAMP = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
CONTENT = {"ciphertext": "Y2lwaGVy", "tag": "dGFn", "nonce": "bm9uY2U="}

LEGACY_FIELDS = {
    "message_id": str(MESSAGE_ID),
    "channel": str(CHANNEL_ID),
    "channel_name": "Pinned Channel",
    "ciphertext": "Y2lwaGVy",
    "tag": "dGFn",
    "nonce": "bm9uY2U=",
    "timestamp": "2026-01-02T03:04:05Z",
    "status": "PENDING",
    "action": "ccc_message",
    "notification_type": "MESSAGING",
    "title": "New Connect Message",
    "body": "You received a new message from Pinned Channel",
}


@pytest.fixture
def server():
    return ServerFactory(server_credentials=ServerKeysFactory())


@pytest.fixture
def channel(user, server):
    return ChannelFactory(channel_id=CHANNEL_ID, connect_user=user, server=server, channel_name="Pinned Channel")


@pytest.fixture
def plain_message(channel):
    return MessageFactory(
        message_id=MESSAGE_ID,
        channel=channel,
        content=CONTENT,
        timestamp=TIMESTAMP,
        direction=MessageDirection.MOBILE,
    )


@pytest.fixture
def rich_message(plain_message):
    plain_message.version = 2
    plain_message.rich_text = {"ciphertext": "cmljaA==", "tag": "dGFn", "nonce": "bm9uY2U="}
    plain_message.format = "gallery"
    plain_message.expires_at = datetime(2026, 2, 1, tzinfo=UTC)
    plain_message.save()
    MessageAttachmentFactory(message=plain_message, name="site-map.jpg", content_type="image/jpeg")
    return plain_message


def pushed_data(user, message):
    """The FCM data payload for a message, sent the way send_fcm and send_rich send it."""
    FCMDeviceFactory(user=user)
    response = messaging.BatchResponse([messaging.SendResponse({"name": "sent"}, None)])
    with mock.patch("firebase_admin.messaging.send_each", return_value=response) as send_each:
        send_bulk_notification_task(usernames=[user.username], data=MessageSerializer(message).data, fcm_options={})
    return send_each.call_args.args[0][0].data


def notification_id_for(message):
    return str(Notification.objects.get(message=message).notification_id)


def test_push(user, plain_message):
    data = pushed_data(user, plain_message)

    assert data == {**LEGACY_FIELDS, "notification_id": notification_id_for(plain_message)}


def test_push_for_a_rich_message_has_only_the_legacy_fields(user, rich_message):
    data = pushed_data(user, rich_message)

    assert data == {**LEGACY_FIELDS, "notification_id": notification_id_for(rich_message)}


def test_retrieve_notifications(user, auth_device, plain_message):
    pushed_data(user, plain_message)

    response = auth_device.get(reverse("messaging:retrieve_notifications"))

    assert response.json()["notifications"] == [
        {**LEGACY_FIELDS, "notification_id": notification_id_for(plain_message)}
    ]


def test_retrieve_notifications_for_a_rich_message_adds_the_rich_fields(user, auth_device, rich_message):
    second = MessageAttachmentFactory(message=rich_message, name="a-second.mp3", content_type="audio/mpeg")
    first = rich_message.attachments.get(name="site-map.jpg")
    pushed_data(user, rich_message)

    response = auth_device.get(reverse("messaging:retrieve_notifications"))

    assert response.json()["notifications"] == [
        {
            **LEGACY_FIELDS,
            "notification_id": notification_id_for(rich_message),
            "version": 2,
            "rich_text": {"ciphertext": "cmljaA==", "tag": "dGFn", "nonce": "bm9uY2U="},
            "format": "gallery",
            "attachments": [
                {"id": str(first.id), "name": "site-map.jpg", "type": "image/jpeg", "size": first.size},
                {"id": str(second.id), "name": "a-second.mp3", "type": "audio/mpeg", "size": second.size},
            ],
            "expires_at": "2026-02-01T00:00:00Z",
        }
    ]


def test_retrieve_notifications_leaves_out_rich_fields_the_sender_did_not_set(user, auth_device, plain_message):
    plain_message.version = 2
    plain_message.expires_at = datetime(2026, 2, 1, tzinfo=UTC)
    plain_message.save()
    pushed_data(user, plain_message)

    response = auth_device.get(reverse("messaging:retrieve_notifications"))

    [entry] = response.json()["notifications"]
    assert {key: entry[key] for key in entry.keys() - LEGACY_FIELDS.keys() - {"notification_id"}} == {
        "version": 2,
        "attachments": [],
        "expires_at": "2026-02-01T00:00:00Z",
    }


def test_retrieve_messages(auth_device, plain_message):
    response = auth_device.get(reverse("messaging:retrieve_messages"))

    assert response.json()["messages"] == [LEGACY_FIELDS]


def test_retrieve_messages_for_a_rich_message_has_only_the_legacy_fields(auth_device, rich_message):
    response = auth_device.get(reverse("messaging:retrieve_messages"))

    assert response.json()["messages"] == [LEGACY_FIELDS]


def test_reply_forwarded_to_the_sender(auth_device, channel):
    reply = {"channel": str(CHANNEL_ID), "message_id": str(MESSAGE_ID), "content": CONTENT}

    with mock.patch("messaging.views.send_messages_to_service_and_mark_status") as forward:
        auth_device.post(reverse("messaging:post_message"), json.dumps(reply), content_type="application/json")

    forwarded = json.loads(json.dumps(forward.call_args.args[0]))
    [message] = forwarded[str(CHANNEL_ID)]["messages"]
    # The reply's timestamp is set when PersonalID stores it; pin its format, and everything else exactly
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z", message.pop("timestamp"))
    assert forwarded == {
        str(CHANNEL_ID): {
            "url": channel.server.delivery_url,
            "messages": [{key: value for key, value in LEGACY_FIELDS.items() if key != "timestamp"}],
        }
    }
