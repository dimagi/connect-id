from unittest import mock

import pytest
from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.db import IntegrityError, transaction

from messaging.factories import MessageAttachmentFactory, MessageFactory, RichMessageFactory
from messaging.models import MessageAttachment
from utils.storage import message_attachment_storage

pytestmark = pytest.mark.django_db


def test_attachments_are_stored_apart_from_photos():
    attachment = MessageAttachmentFactory()

    assert message_attachment_storage.exists(attachment.file.name)
    assert not storages["user_photos"].exists(attachment.file.name)


def test_plain_message_has_no_rich_fields():
    message = MessageFactory()
    message.refresh_from_db()
    assert message.version is None
    assert message.rich_text is None
    assert message.format is None
    assert message.expires_at is None
    assert not message.attachments.exists()


def test_attachment_storage_key_uses_only_personalid_ids():
    message = RichMessageFactory()
    attachment = MessageAttachmentFactory(
        message=message, name="../../escape.jpg", file=ContentFile(b"encrypted", name="../../escape.jpg")
    )

    expected = f"message-attachments/{message.channel_id}/{message.message_id}/{attachment.id}"
    assert attachment.file.name == expected
    with message_attachment_storage.open(expected) as stored:
        assert stored.read() == b"encrypted"


def test_attachment_names_are_unique_within_a_message():
    attachment = MessageAttachmentFactory(name="site-map.jpg")

    MessageAttachmentFactory(name="site-map.jpg")  # same name, another message
    with pytest.raises(IntegrityError), transaction.atomic():
        MessageAttachmentFactory(message=attachment.message, name="site-map.jpg")


def test_deleting_an_attachment_deletes_its_file(django_capture_on_commit_callbacks):
    attachment = MessageAttachmentFactory()
    key = attachment.file.name

    with django_capture_on_commit_callbacks(execute=True):
        attachment.delete()

    assert not message_attachment_storage.exists(key)


def test_deleting_a_message_deletes_its_attachment_files(django_capture_on_commit_callbacks):
    message = RichMessageFactory()
    keys = [MessageAttachmentFactory(message=message).file.name for _ in range(2)]

    with django_capture_on_commit_callbacks(execute=True):
        message.delete()

    assert not MessageAttachment.objects.exists()
    assert not any(message_attachment_storage.exists(key) for key in keys)


def test_deleting_a_channel_deletes_its_attachment_files(django_capture_on_commit_callbacks):
    attachment = MessageAttachmentFactory()
    key = attachment.file.name

    with django_capture_on_commit_callbacks(execute=True):
        attachment.message.channel.delete()

    assert not message_attachment_storage.exists(key)


def test_rolled_back_delete_keeps_the_file(django_capture_on_commit_callbacks):
    attachment = MessageAttachmentFactory()
    pk, key = attachment.pk, attachment.file.name

    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        with pytest.raises(RuntimeError), transaction.atomic():
            attachment.delete()
            raise RuntimeError("roll back")

    assert callbacks == []
    assert MessageAttachment.objects.filter(pk=pk).exists()
    assert message_attachment_storage.exists(key)


def test_storage_failure_on_delete_does_not_raise(django_capture_on_commit_callbacks):
    attachment = MessageAttachmentFactory()

    with (
        mock.patch.object(attachment.file.storage, "delete", side_effect=OSError("storage unavailable")) as delete,
        django_capture_on_commit_callbacks(execute=True),
    ):
        attachment.delete()

    delete.assert_called_once()

    assert not MessageAttachment.objects.filter(pk=attachment.pk).exists()
