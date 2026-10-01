import base64

import sentry_sdk
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage

from users.const import MAX_PHOTO_SIZE, ErrorCodes

# A user's photo is stored as "<username>.<type>" with the type taken from the data URI the app
# sends (today always webp). Reading back checks these types in order.
PHOTO_FILE_TYPES = ("webp", "jpeg", "jpg", "png")


def split_base64_string(image_data):
    """
    Expected format of image_data: data:image/`image_type`;base64,`base64_data`
    """
    header, data = image_data.split(",", 1)
    file_type = header.split(";")[0].split("/")[1]
    return file_type, data


def _photo_name(username, file_type):
    return f"{username}.{file_type}"


def _find_photo_name(username):
    for file_type in PHOTO_FILE_TYPES:
        name = _photo_name(username, file_type)
        if default_storage.exists(name):
            return name
    return None


def upload_photo_to_s3(image_base64, username):
    if len(image_base64) > MAX_PHOTO_SIZE:
        return ErrorCodes.FILE_TOO_LARGE
    file_type, image_base64_data = split_base64_string(image_base64)
    if file_type not in PHOTO_FILE_TYPES:
        return ErrorCodes.FILE_TYPE_UNSUPPORTED
    name = _photo_name(username, file_type)
    try:
        image_data = base64.b64decode(image_base64_data)
        previous = _find_photo_name(username)
        # Write first, so a failed save leaves the previous photo in place. Storage is configured
        # to overwrite on a name collision (see STORAGES), so a same-type replacement is one write.
        saved_name = default_storage.save(name, ContentFile(image_data))
        if saved_name != name:
            raise RuntimeError(f"storage saved {saved_name!r} instead of overwriting {name!r}")
        if previous and previous != name:
            default_storage.delete(previous)
    except Exception as e:
        sentry_sdk.capture_exception(e)
        return ErrorCodes.FAILED_TO_UPLOAD


def get_user_photo_base64(username):
    try:
        name = _find_photo_name(username)
        if name:
            with default_storage.open(name, "rb") as photo:
                image_data = photo.read()
            base64_result = base64.b64encode(image_data).decode("utf-8")
            return f"data:image/{name.rsplit('.', 1)[1]};base64,{base64_result}"
    except Exception as e:
        sentry_sdk.capture_exception(e)
    return ""
