import base64
import json
import uuid
from datetime import timedelta
from unittest import mock

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils.timezone import now
from firebase_admin import messaging
from rest_framework import status

from messaging import local_message_server as lms
from messaging.const import ErrorCodes
from messaging.factories import ChannelFactory, MessageAttachmentFactory, RichMessageFactory, ServerFactory
from messaging.tasks import send_bulk_notification_task
from users.factories import FCMDeviceFactory, ServerKeysFactory

pytestmark = pytest.mark.django_db


def download_url(message_id, attachment_id):
    return reverse("messaging:message_attachment", args=[message_id, attachment_id])


def download(client, attachment):
    return client.get(download_url(attachment.message_id, attachment.id))


@pytest.fixture
def attachment(user):
    message = RichMessageFactory(channel=ChannelFactory(connect_user=user))
    return MessageAttachmentFactory(message=message, name="site-map.jpg")


def test_owner_gets_the_stored_bytes(auth_device, attachment):
    with attachment.file.open("rb") as stored:
        expected = stored.read()

    response = download(auth_device, attachment)

    assert response.status_code == status.HTTP_200_OK
    assert b"".join(response.streaming_content) == expected
    assert response["Content-Type"] == "application/octet-stream"
    assert response["Content-Length"] == str(len(expected))
    # The sender's name, never the storage key
    assert response["Content-Disposition"] == 'inline; filename="site-map.jpg"'


def test_another_users_attachment_is_not_found(auth_device):
    other = MessageAttachmentFactory()  # on a channel belonging to someone else

    assert download(auth_device, other).status_code == status.HTTP_404_NOT_FOUND


def test_unknown_message_is_not_found(auth_device):
    response = auth_device.get(download_url(uuid.uuid4(), uuid.uuid4()))

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_attachment_is_only_found_within_its_own_message(user, auth_device, attachment):
    other_message = RichMessageFactory(channel=attachment.message.channel)
    other_attachment = MessageAttachmentFactory(message=other_message)

    response = auth_device.get(download_url(attachment.message_id, other_attachment.id))

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_expired_message_is_gone(auth_device, attachment):
    attachment.message.expires_at = now() - timedelta(seconds=1)
    attachment.message.save()

    response = download(auth_device, attachment)

    assert response.status_code == status.HTTP_410_GONE
    assert response.json() == {"errors": ErrorCodes.MESSAGE_EXPIRED}


def test_expiry_wins_over_a_missing_attachment(auth_device, attachment):
    attachment.message.expires_at = now() - timedelta(seconds=1)
    attachment.message.save()

    response = auth_device.get(download_url(attachment.message_id, uuid.uuid4()))

    assert response.status_code == status.HTTP_410_GONE


def test_requires_device_authentication(api_client, attachment):
    assert download(api_client, attachment).status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


def test_works_with_rich_sending_switched_off(settings, auth_device, attachment):
    settings.RICH_MESSAGING_ENABLED = False

    assert download(auth_device, attachment).status_code == status.HTTP_200_OK


def test_end_to_end_send_sync_download_decrypt(settings, client, user, auth_device):
    """A sender encrypts and sends; the device syncs, downloads each attachment and decrypts it."""
    settings.RICH_MESSAGING_ENABLED = True
    server = ServerFactory(server_credentials=ServerKeysFactory())
    channel = ChannelFactory(connect_user=user, server=server)
    FCMDeviceFactory(user=user)
    key = lms.new_channel_key()
    files = {"site-map.jpg": b"\xff\xd8 a jpeg", "instructions.mp3": b"ID3 an mp3"}
    blobs = [lms.encrypt_file(key, data) for data in files.values()]
    message = {
        "version": 2,
        "channel": str(channel.channel_id),
        "message_id": str(uuid.uuid4()),
        "content": lms.encrypt(key, "See the attachments"),
        "format": "gallery",
        "attachments": [
            {"name": name, "type": "application/octet-stream", "size": len(blob)} for name, blob in zip(files, blobs)
        ],
    }
    credentials = f"{server.server_credentials.client_id}:{server.server_credentials.secret_key}"

    with (
        mock.patch("messaging.views.send_bulk_notification_task.delay", side_effect=send_bulk_notification_task),
        mock.patch(
            "firebase_admin.messaging.send_each",
            return_value=messaging.BatchResponse([messaging.SendResponse({"name": "sent"}, None)]),
        ),
    ):
        sent = client.post(
            reverse("messaging:send_rich"),
            data={
                "message": json.dumps(message),
                **{f"attachment_{i}": SimpleUploadedFile("x", blob) for i, blob in enumerate(blobs)},
            },
            HTTP_AUTHORIZATION="Basic " + base64.b64encode(credentials.encode()).decode(),
        )
    assert sent.status_code == status.HTTP_200_OK, sent.content

    [entry] = auth_device.get(reverse("messaging:retrieve_notifications")).json()["notifications"]
    assert lms.decrypt(key, entry) == "See the attachments"
    downloaded = {}
    for attachment in entry["attachments"]:
        response = auth_device.get(download_url(entry["message_id"], attachment["id"]))
        assert response.status_code == status.HTTP_200_OK
        blob = b"".join(response.streaming_content)
        assert len(blob) == attachment["size"]
        downloaded[attachment["name"]] = lms.decrypt_file(key, blob)
    assert downloaded == files
    assert [attachment["name"] for attachment in entry["attachments"]] == list(files)
