import base64

import boto3
import sentry_sdk
from django.conf import settings

from users.const import MAX_PHOTO_SIZE, ErrorCodes


def upload_photo_to_s3(image_base64, user_id):
    if len(image_base64) > MAX_PHOTO_SIZE:
        return ErrorCodes.FILE_TOO_LARGE
    filename = f"{user_id}.jpg"
    s3_client = boto3.client("s3")
    try:
        image_data = base64.b64decode(image_base64)
        s3_client.put_object(
            Bucket=settings.AWS_S3_PHOTO_BUCKET_NAME,
            Key=filename,
            Body=image_data,
            ContentType="image/jpeg",
        )
    except Exception as e:
        sentry_sdk.capture_exception(e)
        return ErrorCodes.FAILED_TO_UPLOAD
