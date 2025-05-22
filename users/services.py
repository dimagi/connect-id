import base64

import boto3
import sentry_sdk
from django.conf import settings

from users.const import MAX_PHOTO_SIZE, ErrorCodes


def split_base64_string(image_data):
    """
    Expected format of image_data: data:image/`image_type`;base64,`base64_data`
    """
    header, data = image_data.split(",", 1)
    file_type = header.split(";")[0].split("/")[1]
    return file_type, data


def upload_photo_to_s3(image_base64, user_id):
    if len(image_base64) > MAX_PHOTO_SIZE:
        return ErrorCodes.FILE_TOO_LARGE
    file_type, image_base64_data = split_base64_string(image_base64)
    filename = f"{user_id}.{file_type}"
    s3_client = boto3.client("s3")
    try:
        image_data = base64.b64decode(image_base64_data)
        s3_client.put_object(
            Bucket=settings.AWS_S3_PHOTO_BUCKET_NAME,
            Key=filename,
            Body=image_data,
            ContentType=f"image/{file_type}",
        )
    except Exception as e:
        sentry_sdk.capture_exception(e)
        return ErrorCodes.FAILED_TO_UPLOAD
