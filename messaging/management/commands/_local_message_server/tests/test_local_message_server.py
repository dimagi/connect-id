import json
from io import StringIO
from unittest import mock

import pytest
import requests
from django.core.management import call_command
from django.core.management.base import CommandError
from django.urls import reverse
from django.utils import timezone
from firebase_admin import messaging
from oauth2_provider.models import Application

from messaging.const import MESSAGING_VERSION, MESSAGING_VERSION_HEADER
from messaging.factories import (
    ChannelFactory,
    MessageAttachmentFactory,
    MessageFactory,
    RichMessageFactory,
    ServerFactory,
)
from messaging.management.commands._local_message_server import server as lms
from messaging.models import Message, MessageDirection, MessageServer, Notification
from messaging.serializers import MessageSerializer
from messaging.tasks import mac_digest
from users.factories import ServerKeysFactory, UserFactory
from utils.storage import message_attachment_storage


def run(**options):
    out = StringIO()
    call_command("local_message_server", setup_only=True, stdout=out, **options)
    return out.getvalue()


@pytest.mark.django_db
def test_refuses_without_debug(settings):
    settings.DEBUG = False
    with pytest.raises(CommandError):
        run()


@pytest.mark.django_db
def test_setup_creates_the_app_and_a_server_and_is_idempotent(settings):
    settings.DEBUG = True

    run(public_url="http://sender.test:9000/")
    run(public_url="http://sender.test:9000/")

    app = Application.objects.get(client_id=lms.ANDROID_CLIENT_ID)
    assert app.client_type == Application.CLIENT_PUBLIC
    assert app.authorization_grant_type == Application.GRANT_PASSWORD
    assert app.algorithm == Application.HS256_ALGORITHM

    server = MessageServer.objects.get(name=lms.SERVER_NAME)
    assert server.key_url == "http://sender.test:9000/key"
    assert server.delivery_url == "http://sender.test:9000/delivery"
    assert server.server_credentials is not None
    assert MessageServer.objects.filter(name=lms.SERVER_NAME).count() == 1


@pytest.mark.django_db
def test_lists_users_with_demo_users_first(settings):
    settings.DEBUG = True
    regular = UserFactory(phone_number="+12025550100")
    demo = UserFactory(phone_number="+74261234567", name="Demo Person")

    output = run()

    assert output.index(demo.username) < output.index(regular.username)
    assert f"{demo.username}  *******rson" in output
    assert "4567" not in output
    assert "Demo Person" not in output
    assert output.count("(demo)") == 1


@pytest.mark.parametrize(
    "value, expected",
    [
        ("+99991234567", "********4567"),
        ("John Smith", "******mith"),
        ("1234", "****"),
        ("ab", "**"),
        ("", ""),
        (None, ""),
    ],
)
def test_mask_keeps_only_the_last_four_characters(value, expected):
    assert lms.mask(value) == expected


def test_encrypt_round_trips_through_the_relayed_triple():
    key = lms.new_channel_key()
    triple = lms.encrypt(key, "héllo")

    assert set(triple) == {"ciphertext", "tag", "nonce"}
    assert lms.decrypt(key, triple) == "héllo"


@pytest.mark.django_db
def test_inbound_signature_uses_personalid_own_digest(tmp_path):
    credentials = mock.Mock(client_id="id", secret_key="s3cret")
    sender = lms.Sender("http://personalid.test", credentials, lms.State(tmp_path / "state.json"))
    body = json.dumps({"channel_id": "c1", "messages": []}).encode()

    assert sender.verify_mac(body, mac_digest("s3cret", body))
    assert not sender.verify_mac(body, mac_digest("other", body))
    assert not sender.verify_mac(body, None)


@pytest.mark.django_db
def test_key_is_served_only_to_the_channel_owner(tmp_path):
    credentials = mock.Mock(client_id="id", secret_key="s3cret")
    state = lms.State(tmp_path / "state.json")
    state.channels["c1"] = {"connectid": "AbC123", "key": lms.new_channel_key()}
    state.save()
    sender = lms.Sender("http://personalid.test", credentials, state)

    with mock.patch.object(sender, "username_for_token", return_value="abc123"):
        assert sender.serve_key({"channel_id": ["c1"]}, "Bearer t")[0] == 200
    with mock.patch.object(sender, "username_for_token", return_value="someoneelse"):
        assert sender.serve_key({"channel_id": ["c1"]}, "Bearer t")[0] == 401
    with mock.patch.object(sender, "username_for_token", return_value=None):
        assert sender.serve_key({"channel_id": ["c1"]}, "Bearer t")[0] == 401
    assert sender.serve_key({"channel_id": ["nope"]}, "Bearer t")[0] == 404
    assert sender.serve_key({}, None)[0] == 400


@pytest.mark.django_db
def test_user_listing_refuses_without_debug(settings):
    settings.DEBUG = False
    with pytest.raises(RuntimeError):
        lms.print_users(lambda line: None)


def test_file_encryption_uses_the_attachment_layout():
    key = lms.new_channel_key()
    blob = lms.encrypt_file(key, b"\x00image bytes")

    assert len(blob) == len(b"\x00image bytes") + 28
    assert lms.decrypt_file(key, blob) == b"\x00image bytes"


def write_fixture(folder, **files):
    folder.mkdir()
    for name, content in files.items():
        path = folder / name.replace("__", ".")
        path.write_bytes(content) if isinstance(content, bytes) else path.write_text(content)
    return folder


def test_fixture_reads_texts_fields_and_attachments_in_name_order(tmp_path):
    folder = write_fixture(
        tmp_path / "m",
        content__txt="**text**\n",
        legacy__txt="please update\n",
        message__json='{"format": "gallery"}',
        b__png=b"png",
        a__mp3=b"mp3",
        notes__unknownext=b"?",
        **{".DS_Store": b"skip"},
    )

    content, legacy, fields, attachments = lms.load_rich_fixture(folder)

    assert (content, legacy, fields) == ("**text**", "please update", {"format": "gallery"})
    assert attachments == [
        ("a.mp3", "audio/mpeg", b"mp3"),
        ("b.png", "image/png", b"png"),
        ("notes.unknownext", "application/octet-stream", b"?"),
    ]


def test_fixture_texts_are_optional(tmp_path):
    content, legacy, _, attachments = lms.load_rich_fixture(write_fixture(tmp_path / "m", a__png=b"png"))

    assert (content, legacy) == (None, None)
    assert [name for name, _, _ in attachments] == ["a.png"]


def test_fixture_refuses_the_retired_rich_text_file(tmp_path):
    with pytest.raises(lms.FixtureError, match="rich_text.md"):
        lms.load_rich_fixture(write_fixture(tmp_path / "m", content__txt="x", rich_text__md="y"))


@pytest.mark.django_db
def test_send_rich_is_accepted_by_personalid(tmp_path, settings, client):
    """The sender's request, replayed through the real endpoint, stores a message the device can decrypt."""
    settings.RICH_MESSAGING_ENABLED = True
    server = ServerFactory(server_credentials=ServerKeysFactory())
    channel = ChannelFactory(server=server)
    state = lms.State(tmp_path / "state.json")
    key = lms.new_channel_key()
    state.channels[str(channel.channel_id)] = {"connectid": channel.connect_user.username, "key": key}
    sender = lms.Sender("http://personalid.test", server.server_credentials, state)
    folder = write_fixture(
        tmp_path / "m",
        content__txt="the text",
        legacy__txt="please update",
        message__json='{"format": "gallery"}',
        a__png=b"png",
    )

    def through_django(url, files, auth, headers, timeout):
        """Hand the multipart request requests would send to Django's test client instead."""
        assert headers == {MESSAGING_VERSION_HEADER: str(MESSAGING_VERSION)}
        prepared = requests.Request("POST", url, files=files, auth=auth, headers=headers).prepare()
        response = client.generic(
            "POST",
            "/messaging/create_message/",
            prepared.body,
            content_type=prepared.headers["Content-Type"],
            HTTP_AUTHORIZATION=prepared.headers["Authorization"],
            headers={MESSAGING_VERSION_HEADER: prepared.headers[MESSAGING_VERSION_HEADER]},
        )
        return mock.Mock(status_code=response.status_code, text=response.content.decode())

    with (
        mock.patch.object(lms.requests, "post", side_effect=through_django),
        mock.patch("messaging.views.send_bulk_notification_task"),
    ):
        message_id = sender.send_rich(str(channel.channel_id), folder)

    assert message_id
    message = Message.objects.get(message_id=message_id)
    assert lms.decrypt(key, message.content) == "please update"
    assert lms.decrypt(key, message.rich_text) == "the text"
    assert message.format == "gallery"
    attachment = message.attachments.get()
    assert (attachment.name, attachment.content_type) == ("a.png", "image/png")
    with message_attachment_storage.open(attachment.file.name) as stored:
        assert lms.decrypt_file(key, stored.read()) == b"png"


@pytest.mark.django_db
def test_future_version_message_reaches_the_sync(tmp_path, user, auth_device):
    channel = ChannelFactory(connect_user=user)
    key = lms.new_channel_key()
    state = lms.State(tmp_path / "state.json")
    state.channels[str(channel.channel_id)] = {"connectid": user.username, "key": key}
    state.last = str(channel.channel_id)
    sender = lms.Sender("http://personalid.test", mock.Mock(client_id="id", secret_key="s"), state)

    with mock.patch(
        "firebase_admin.messaging.send_each",
        return_value=messaging.BatchResponse([messaging.SendResponse({"name": "sent"}, None)]),
    ):
        message_id = sender.send_future_version("last")

    [entry] = auth_device.get(reverse("messaging:retrieve_notifications")).json()["notifications"]
    assert entry["message_id"] == message_id
    assert entry["version"] == MESSAGING_VERSION + 1
    assert "update notice" in lms.decrypt(key, entry)
    assert "never show" in lms.decrypt(key, entry["rich_text"])
    assert entry["attachments"] == []


@pytest.mark.django_db
def test_clear_pending_deletes_only_unacked_messages_to_the_phone(tmp_path, django_capture_on_commit_callbacks):
    channel = ChannelFactory()
    state = lms.State(tmp_path / "state.json")
    key = lms.new_channel_key()
    state.channels[str(channel.channel_id)] = {"connectid": channel.connect_user.username, "key": key}
    sender = lms.Sender("http://personalid.test", mock.Mock(client_id="id", secret_key="s"), state)

    def to_phone(received):
        message = RichMessageFactory(channel=channel, direction=MessageDirection.MOBILE)
        # Created the way the push path creates it (utils.notification._get_or_create_notification)
        notification = Notification(user=channel.connect_user, json={"data": MessageSerializer(message).data})
        notification.save()
        Notification.objects.filter(pk=notification.pk).update(received=received)
        return message

    pending = to_phone(received=None)
    attachment = MessageAttachmentFactory(message=pending)
    delivered = to_phone(received=timezone.now())
    reply = MessageFactory(channel=channel, direction=MessageDirection.SERVER)
    other_channel = MessageFactory(direction=MessageDirection.MOBILE)

    with django_capture_on_commit_callbacks(execute=True):
        assert sender.clear_pending(str(channel.channel_id)) == 1

    assert set(Message.objects.values_list("message_id", flat=True)) == {
        delivered.message_id,
        reply.message_id,
        other_channel.message_id,
    }
    assert not Notification.objects.filter(message_id=pending.message_id).exists()
    assert not message_attachment_storage.exists(attachment.file.name)
