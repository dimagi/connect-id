import base64

import boto3
from django.conf import settings


def upload_photo_to_s3(image_base64, user_id):
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
    except Exception:
        return False
    return True
