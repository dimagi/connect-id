"""Photo storage through the user_photos bucket. conftest points every bucket at a temp directory."""

import base64

from django.conf import settings
from django.core.files.storage import storages
from django.utils.module_loading import import_string

from users.const import ErrorCodes
from users.services import get_user_photo_base64, upload_photo_to_s3

PHOTO_BYTES = b"not really a jpeg"
PHOTO_DATA_URI = "data:image/jpeg;base64," + base64.b64encode(PHOTO_BYTES).decode()


def test_photo_is_saved_and_read_back():
    assert upload_photo_to_s3(PHOTO_DATA_URI, "someuser") is None

    assert storages["user_photos"].open("someuser.jpeg").read() == PHOTO_BYTES
    assert get_user_photo_base64("someuser") == PHOTO_DATA_URI


def test_a_new_photo_replaces_the_old_one_whatever_its_type():
    upload_photo_to_s3(PHOTO_DATA_URI, "someuser")
    webp = "data:image/webp;base64," + base64.b64encode(b"webp bytes").decode()

    upload_photo_to_s3(webp, "someuser")

    assert not storages["user_photos"].exists("someuser.jpeg")
    assert get_user_photo_base64("someuser") == webp


def test_saving_twice_overwrites_rather_than_renaming():
    upload_photo_to_s3(PHOTO_DATA_URI, "someuser")
    second = "data:image/jpeg;base64," + base64.b64encode(b"second").decode()

    upload_photo_to_s3(second, "someuser")

    assert storages["user_photos"].open("someuser.jpeg").read() == b"second"
    assert storages["user_photos"].listdir("")[1] == ["someuser.jpeg"]


def test_missing_photo_reads_as_empty():
    assert get_user_photo_base64("nobody") == ""


def test_size_limit_still_applies():
    oversized = "data:image/jpeg;base64," + "A" * 2_000_000
    assert upload_photo_to_s3(oversized, "someuser") == ErrorCodes.FILE_TOO_LARGE


def test_bad_base64_is_reported_not_raised():
    assert upload_photo_to_s3("data:image/png;base64,invalid-base64", "someuser") == ErrorCodes.FAILED_TO_UPLOAD


def test_production_storage_backend_exists():
    """Tests run on FileSystemStorage, so make sure the production backend path at least imports."""
    backend = import_string(settings.PRODUCTION_FILE_STORAGE_BACKEND)
    assert backend.__name__ == "S3Storage"


def test_unsupported_type_is_refused_before_anything_is_written():
    upload_photo_to_s3(PHOTO_DATA_URI, "someuser")
    bad = "data:image/tiff;base64," + base64.b64encode(b"tiff bytes").decode()

    assert upload_photo_to_s3(bad, "someuser") == ErrorCodes.FILE_TYPE_UNSUPPORTED

    assert storages["user_photos"].listdir("")[1] == ["someuser.jpeg"]
    assert get_user_photo_base64("someuser") == PHOTO_DATA_URI


def test_failed_write_keeps_the_previous_photo(monkeypatch):
    upload_photo_to_s3(PHOTO_DATA_URI, "someuser")

    def failing_save(name, content):
        raise OSError("disk full")

    monkeypatch.setattr(storages["user_photos"], "save", failing_save)
    webp = "data:image/webp;base64," + base64.b64encode(b"webp bytes").decode()

    assert upload_photo_to_s3(webp, "someuser") == ErrorCodes.FAILED_TO_UPLOAD
    assert get_user_photo_base64("someuser") == PHOTO_DATA_URI
