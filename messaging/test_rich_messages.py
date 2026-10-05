import base64
import json
import uuid
from datetime import timedelta
from pathlib import Path
from unittest import mock

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils.timezone import now
from rest_framework import status

from messaging import rich_messages
from messaging.const import DEFAULT_RICH_MESSAGE_EXPIRY, ErrorCodes
from messaging.factories import ChannelFactory, MessageFactory, ServerFactory
from messaging.models import Message, MessageAttachment
from messaging.serializers import MessageSerializer
from users.factories import ServerKeysFactory
from utils.storage import message_attachment_storage

URL = reverse("messaging:send_rich")
SITE_MAP = b"\x01" * 100
INSTRUCTIONS = b"\x02" * 200


def encrypted(text="..."):
    return {"ciphertext": base64.b64encode(text.encode()).decode(), "tag": "dGFn", "nonce": "bm9uY2U="}


@pytest.fixture
def server(db):
    return ServerFactory(server_credentials=ServerKeysFactory())


@pytest.fixture
def channel(user, server):
    return ChannelFactory(connect_user=user, server=server)


@pytest.fixture
def enabled(settings):
    settings.RICH_MESSAGING_ENABLED = True


def auth(server):
    credentials = f"{server.server_credentials.client_id}:{server.server_credentials.secret_key}"
    return {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(credentials.encode()).decode()}


def payload(channel, **overrides):
    message = {
        "version": 2,
        "channel": str(channel.channel_id),
        "message_id": str(uuid.uuid4()),
        "content": encrypted("Here is the site map"),
        "rich_text": encrypted("Here is the **site map**"),
        "format": "gallery",
        "attachments": [
            {"name": "site-map.jpg", "type": "image/jpeg", "size": len(SITE_MAP)},
            {"name": "instructions.mp3", "type": "audio/mpeg", "size": len(INSTRUCTIONS)},
        ],
        "expires_at": (now() + timedelta(days=7)).isoformat(),
    }
    message.update(overrides)
    return message


def parts(*contents):
    return {f"attachment_{i}": SimpleUploadedFile(f"upload-{i}", content) for i, content in enumerate(contents)}


def post(client, server, message, files=None, **extra):
    data = {"message": json.dumps(message), **(parts(SITE_MAP, INSTRUCTIONS) if files is None else files)}
    with mock.patch("messaging.views.send_bulk_notification_task") as push:
        response = client.post(URL, data=data, **auth(server), **extra)
    return response, push


def assert_rejected(response, code, status_code=status.HTTP_400_BAD_REQUEST):
    assert response.status_code == status_code, response.content
    assert response.json()["errors"] == code
    assert not Message.objects.exists()
    assert not MessageAttachment.objects.exists()


@pytest.mark.usefixtures("enabled")
class TestSendRichMessage:
    def test_stores_message_and_attachments_and_pushes(self, client, server, channel):
        message = payload(channel)

        response, push = post(client, server, message)

        assert response.status_code == status.HTTP_200_OK, response.content
        assert response.json() == {"message_id": message["message_id"]}
        stored = Message.objects.get(message_id=message["message_id"])
        assert stored.channel == channel
        assert stored.content == message["content"]
        assert stored.rich_text == message["rich_text"]
        assert (stored.version, stored.format) == (2, "gallery")
        assert stored.expires_at.isoformat() == message["expires_at"]

        # In the order sent, not by name
        assert [a.name for a in stored.attachments.all()] == ["site-map.jpg", "instructions.mp3"]
        attachments = {a.name: a for a in stored.attachments.all()}
        assert {name: (a.content_type, a.size) for name, a in attachments.items()} == {
            "site-map.jpg": ("image/jpeg", len(SITE_MAP)),
            "instructions.mp3": ("audio/mpeg", len(INSTRUCTIONS)),
        }
        with message_attachment_storage.open(attachments["site-map.jpg"].file.name) as f:
            assert f.read() == SITE_MAP
        with message_attachment_storage.open(attachments["instructions.mp3"].file.name) as f:
            assert f.read() == INSTRUCTIONS

        # The push is the same projection a plain message gets: no rich fields
        push.delay.assert_called_once_with(
            usernames=[channel.connect_user.username], data=MessageSerializer(stored).data, fcm_options={}
        )
        assert "attachments" not in push.delay.call_args.kwargs["data"]

    def test_message_without_attachments_or_optional_fields(self, client, server, channel):
        message = payload(channel, attachments=[])
        for field in ("rich_text", "format", "expires_at"):
            del message[field]

        response, _ = post(client, server, message, files={})

        assert response.status_code == status.HTTP_200_OK, response.content
        stored = Message.objects.get(message_id=message["message_id"])
        assert (stored.rich_text, stored.format) == (None, None)
        assert not stored.attachments.exists()
        assert abs(stored.expires_at - (now() + DEFAULT_RICH_MESSAGE_EXPIRY)) < timedelta(minutes=1)

    def test_part_filenames_are_ignored(self, client, server, channel):
        files = {
            "attachment_0": SimpleUploadedFile("../../elsewhere.jpg", SITE_MAP),
            "attachment_1": SimpleUploadedFile("x", INSTRUCTIONS),
        }

        response, _ = post(client, server, payload(channel), files=files)

        assert response.status_code == status.HTTP_200_OK, response.content
        attachment = MessageAttachment.objects.get(name="site-map.jpg")
        assert attachment.file.name.endswith(f"/{attachment.message_id}/{attachment.id}")


@pytest.mark.usefixtures("enabled")
class TestRejections:
    def test_disabled(self, client, server, channel, settings):
        settings.RICH_MESSAGING_ENABLED = False
        response, _ = post(client, server, payload(channel))
        assert_rejected(response, ErrorCodes.RICH_MESSAGING_DISABLED, status.HTTP_403_FORBIDDEN)

    def test_wrong_credentials(self, client, channel):
        other = ServerFactory(server_credentials=ServerKeysFactory())
        other.server_credentials.secret_key = "wrong"
        response, _ = post(client, other, payload(channel))
        assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)
        assert not Message.objects.exists()

    def test_declared_length_over_limit(self, client, server, channel, monkeypatch):
        monkeypatch.setattr(rich_messages, "MAX_MESSAGE_ATTACHMENT_BYTES", 10)
        monkeypatch.setattr(rich_messages, "MAX_RICH_REQUEST_OVERHEAD_BYTES", 10)
        response, _ = post(client, server, payload(channel))
        assert_rejected(response, ErrorCodes.REQUEST_TOO_LARGE, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    def test_missing_json_part(self, client, server):
        with mock.patch("messaging.views.send_bulk_notification_task"):
            response = client.post(URL, data=parts(SITE_MAP), **auth(server))
        assert_rejected(response, ErrorCodes.INVALID_RICH_MESSAGE)

    def test_json_part_is_not_json(self, client, server):
        response = client.post(URL, data={"message": "{not json"}, **auth(server))
        assert_rejected(response, ErrorCodes.INVALID_RICH_MESSAGE)

    @pytest.mark.parametrize("version", [None, 1, 3, "2"])
    def test_unsupported_version(self, client, server, channel, version):
        message = payload(channel, version=version)
        if version is None:
            del message["version"]
        response, _ = post(client, server, message)
        assert_rejected(response, ErrorCodes.UNSUPPORTED_VERSION)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"content": None},
            {"content": {"ciphertext": "", "tag": "dGFn", "nonce": "bm9uY2U="}},
            {"rich_text": {"ciphertext": "abc"}},
            {"message_id": "not-a-uuid"},
            {"attachments": [{"name": "a.jpg", "type": "image/jpeg"}]},
            {"attachments": [{"name": "a.jpg", "type": "image/jpeg", "size": 0}]},
        ],
    )
    def test_malformed_message(self, client, server, channel, overrides):
        response, _ = post(client, server, payload(channel, **overrides))
        assert_rejected(response, ErrorCodes.INVALID_RICH_MESSAGE)
        assert "detail" in response.json()

    def test_too_many_attachments(self, client, server, channel):
        attachments = [{"name": f"{i}.jpg", "type": "image/jpeg", "size": 1} for i in range(11)]
        files = parts(*[b"x"] * 11)
        response, _ = post(client, server, payload(channel, attachments=attachments), files=files)
        assert_rejected(response, ErrorCodes.TOO_MANY_ATTACHMENTS)

    def test_duplicate_names(self, client, server, channel):
        attachments = [{"name": "same.jpg", "type": "image/jpeg", "size": len(SITE_MAP)}] * 2
        response, _ = post(client, server, payload(channel, attachments=attachments), files=parts(SITE_MAP, SITE_MAP))
        assert_rejected(response, ErrorCodes.DUPLICATE_ATTACHMENT_NAME)

    def test_attachment_over_limit(self, client, server, channel, monkeypatch):
        monkeypatch.setattr(rich_messages, "MAX_ATTACHMENT_BYTES", len(INSTRUCTIONS) - 1)
        response, _ = post(client, server, payload(channel))
        assert_rejected(response, ErrorCodes.ATTACHMENT_TOO_LARGE)

    def test_message_over_limit(self, client, server, channel, monkeypatch):
        monkeypatch.setattr(rich_messages, "MAX_MESSAGE_ATTACHMENT_BYTES", len(SITE_MAP) + len(INSTRUCTIONS) - 1)
        response, _ = post(client, server, payload(channel))
        assert_rejected(response, ErrorCodes.MESSAGE_TOO_LARGE)

    @pytest.mark.parametrize(
        "files",
        [
            parts(SITE_MAP),  # one missing
            parts(SITE_MAP, INSTRUCTIONS, b"extra"),  # one too many
            {"attachment_0": SimpleUploadedFile("a", SITE_MAP), "attachment_2": SimpleUploadedFile("b", INSTRUCTIONS)},
            {"site-map.jpg": SimpleUploadedFile("a", SITE_MAP), "attachment_1": SimpleUploadedFile("b", INSTRUCTIONS)},
        ],
    )
    def test_parts_do_not_match_attachments(self, client, server, channel, files):
        response, _ = post(client, server, payload(channel), files=files)
        assert_rejected(response, ErrorCodes.ATTACHMENT_PARTS_MISMATCH)

    def test_part_size_differs_from_declared(self, client, server, channel):
        response, _ = post(client, server, payload(channel), files=parts(SITE_MAP, INSTRUCTIONS + b"!"))
        assert_rejected(response, ErrorCodes.ATTACHMENT_SIZE_MISMATCH)

    @pytest.mark.parametrize("expires_in", [timedelta(seconds=-1), timedelta(days=91)])
    def test_expiry_out_of_range(self, client, server, channel, expires_in):
        message = payload(channel, expires_at=(now() + expires_in).isoformat())
        response, _ = post(client, server, message)
        assert_rejected(response, ErrorCodes.INVALID_EXPIRY)

    def test_unknown_channel(self, client, server, channel):
        message = payload(channel)
        message["channel"] = str(uuid.uuid4())
        response, _ = post(client, server, message)
        assert_rejected(response, ErrorCodes.CHANNEL_DOES_NOT_EXIST)

    def test_channel_of_another_server(self, client, server, user):
        other_channel = ChannelFactory(connect_user=user, server=ServerFactory(server_credentials=ServerKeysFactory()))
        response, _ = post(client, server, payload(other_channel))
        assert_rejected(response, ErrorCodes.CHANNEL_DOES_NOT_EXIST)

    def test_no_consent(self, client, server, channel):
        channel.user_consent = False
        channel.save()
        response, _ = post(client, server, payload(channel))
        assert_rejected(response, ErrorCodes.NO_USER_CONSENT)

    def test_message_id_taken_writes_no_files(self, client, server, channel):
        existing = MessageFactory()
        with mock.patch.object(MessageAttachment.file.field.storage, "save") as save:
            response, _ = post(client, server, payload(channel, message_id=str(existing.message_id)))
        assert response.json()["errors"] == ErrorCodes.MESSAGE_ID_ALREADY_EXISTS
        save.assert_not_called()

    def test_files_are_removed_when_the_database_write_fails(self, client, server, channel):
        storage = MessageAttachment.file.field.storage
        with (
            mock.patch.object(storage, "save", wraps=storage.save) as save,
            mock.patch.object(MessageAttachment.objects, "bulk_create", side_effect=RuntimeError("db down")),
            pytest.raises(RuntimeError),
        ):
            post(client, server, payload(channel))

        assert save.call_count == 2
        assert not Message.objects.exists()
        assert [path for path in Path(message_attachment_storage.location).rglob("*") if path.is_file()] == []
