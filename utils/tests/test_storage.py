import pytest
from django.core.files.storage import InvalidStorageError, default_storage, storages

from connectid.settings import LOCAL_FILE_STORAGE_BACKEND, PRODUCTION_FILE_STORAGE_BACKEND, bucket_storage
from utils.storage import message_attachment_storage


def test_buckets_are_configured_by_name(tmp_path):
    assert bucket_storage("attachments", PRODUCTION_FILE_STORAGE_BACKEND) == {
        "BACKEND": PRODUCTION_FILE_STORAGE_BACKEND,
        "OPTIONS": {"bucket_name": "attachments"},
    }
    assert bucket_storage("attachments", LOCAL_FILE_STORAGE_BACKEND, tmp_path) == {
        "BACKEND": LOCAL_FILE_STORAGE_BACKEND,
        "OPTIONS": {"location": tmp_path / "attachments", "allow_overwrite": True},
    }


def test_every_bucket_has_its_own_location():
    assert storages["user_photos"].location != storages["message_attachments"].location


def test_attachment_field_storage_follows_storages_changes(settings, tmp_path):
    """The lazy wrapper exists so a FileField picks up STORAGES overrides; check that it does."""
    settings.STORAGES = {
        **settings.STORAGES,
        "message_attachments": {
            **settings.STORAGES["message_attachments"],
            "OPTIONS": {"location": tmp_path / "moved"},
        },
    }
    assert message_attachment_storage.location == str(tmp_path / "moved")


def test_there_is_no_default_storage():
    """Code that stores files names its bucket; nothing falls through to a general-purpose one."""
    with pytest.raises(InvalidStorageError):
        default_storage.exists("anything")
