import base64
from unittest import mock

import pytest

from users.const import ErrorCodes
from users.services import get_user_photo_base64, upload_photo_to_s3

PHOTO_BYTES = b"not really a jpeg"
PHOTO_DATA_URI = "data:image/jpeg;base64," + base64.b64encode(PHOTO_BYTES).decode()


@pytest.fixture
def local_mode(settings, tmp_path):
    settings.LOCAL_MODE = True
    settings.LOCAL_BLOB_ROOT = tmp_path
    settings.AWS_S3_PHOTO_BUCKET_NAME = "photo-bucket"


@pytest.mark.usefixtures("local_mode")
class TestPhotosInLocalMode:
    @mock.patch("users.services.boto3.client", side_effect=AssertionError("S3 in LOCAL_MODE"))
    def test_photo_is_written_under_the_bucket_name_and_read_back(self, _boto3, tmp_path):
        assert upload_photo_to_s3(PHOTO_DATA_URI, "someuser") is None

        assert (tmp_path / "photo-bucket" / "someuser.jpeg").read_bytes() == PHOTO_BYTES
        assert get_user_photo_base64("someuser") == PHOTO_DATA_URI

    def test_missing_photo_reads_as_empty(self):
        assert get_user_photo_base64("nobody") == ""

    def test_size_limit_still_applies(self):
        oversized = "data:image/jpeg;base64," + "A" * 2_000_000
        assert upload_photo_to_s3(oversized, "someuser") == ErrorCodes.FILE_TOO_LARGE
