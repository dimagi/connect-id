"""Receiving rich messages: a message with encrypted attachments, sent in one multipart request.

The request has a "message" part holding JSON (see SendRichMessageSerializer) and one part per
attachment, named attachment_0, attachment_1, ... in the order of the "attachments" list. The
part's own filename is ignored; the JSON's "name" is the attachment's name.
"""

import json

import sentry_sdk
from django.db import transaction
from django.utils.timezone import now
from rest_framework import status

from messaging.const import (
    DEFAULT_RICH_MESSAGE_EXPIRY,
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS_PER_MESSAGE,
    MAX_MESSAGE_ATTACHMENT_BYTES,
    MAX_RICH_MESSAGE_EXPIRY,
    MAX_RICH_REQUEST_OVERHEAD_BYTES,
    RICH_MESSAGE_VERSION,
    ErrorCodes,
)
from messaging.models import Message, MessageAttachment, MessageDirection
from messaging.serializers import SendRichMessageSerializer
from utils.storage import message_attachment_storage


class RichMessageRejected(Exception):
    def __init__(self, code, status_code=status.HTTP_400_BAD_REQUEST, detail=None):
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.detail = detail

    @property
    def body(self):
        body = {"errors": self.code}
        if self.detail is not None:
            body["detail"] = self.detail
        return body


def attachment_part_name(index):
    return f"attachment_{index}"


def check_request_size(meta):
    """Refuse an oversized request from its declared length, before the body is parsed.

    Django reads the whole multipart body (spooling large parts to disk) the first time the
    request's data is touched, so this must run first.
    """
    try:
        declared = int(meta.get("CONTENT_LENGTH") or 0)
    except ValueError:
        declared = 0
    if declared > MAX_MESSAGE_ATTACHMENT_BYTES + MAX_RICH_REQUEST_OVERHEAD_BYTES:
        raise RichMessageRejected(ErrorCodes.REQUEST_TOO_LARGE, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)


def parse_rich_message(data, files):
    """Validate the JSON part against the uploaded parts. Returns the message with expires_at set."""
    raw = data.get("message")
    if not isinstance(raw, str):
        raise RichMessageRejected(ErrorCodes.INVALID_RICH_MESSAGE, detail={"message": "Missing JSON part."})
    try:
        payload = json.loads(raw)
    except ValueError:
        raise RichMessageRejected(ErrorCodes.INVALID_RICH_MESSAGE, detail={"message": "Not valid JSON."})
    if not isinstance(payload, dict):
        raise RichMessageRejected(ErrorCodes.INVALID_RICH_MESSAGE, detail={"message": "Not a JSON object."})

    # The version decides the rest of the shape, so it is checked first
    if payload.get("version") != RICH_MESSAGE_VERSION:
        raise RichMessageRejected(ErrorCodes.UNSUPPORTED_VERSION)

    serializer = SendRichMessageSerializer(data=payload)
    if not serializer.is_valid():
        raise RichMessageRejected(ErrorCodes.INVALID_RICH_MESSAGE, detail=serializer.errors)
    message = serializer.validated_data
    attachments = message["attachments"]

    if len(attachments) > MAX_ATTACHMENTS_PER_MESSAGE:
        raise RichMessageRejected(ErrorCodes.TOO_MANY_ATTACHMENTS)
    names = [attachment["name"] for attachment in attachments]
    if len(set(names)) != len(names):
        raise RichMessageRejected(ErrorCodes.DUPLICATE_ATTACHMENT_NAME)
    if any(attachment["size"] > MAX_ATTACHMENT_BYTES for attachment in attachments):
        raise RichMessageRejected(ErrorCodes.ATTACHMENT_TOO_LARGE)
    if sum(attachment["size"] for attachment in attachments) > MAX_MESSAGE_ATTACHMENT_BYTES:
        raise RichMessageRejected(ErrorCodes.MESSAGE_TOO_LARGE)

    expected_parts = {attachment_part_name(index) for index in range(len(attachments))}
    if set(files.keys()) != expected_parts or any(len(files.getlist(part)) != 1 for part in expected_parts):
        raise RichMessageRejected(ErrorCodes.ATTACHMENT_PARTS_MISMATCH)
    for index, attachment in enumerate(attachments):
        if files[attachment_part_name(index)].size != attachment["size"]:
            raise RichMessageRejected(ErrorCodes.ATTACHMENT_SIZE_MISMATCH)

    current_time = now()
    expires_at = message.get("expires_at") or current_time + DEFAULT_RICH_MESSAGE_EXPIRY
    if not current_time < expires_at <= current_time + MAX_RICH_MESSAGE_EXPIRY:
        raise RichMessageRejected(ErrorCodes.INVALID_EXPIRY)
    message["expires_at"] = expires_at
    return message


def store_rich_message(channel, message_data, files):
    """Write the attachment files, then the message and attachment rows in one transaction.

    Files are written before the transaction so it is not held open during uploads to storage. If
    anything fails afterwards, the files already written are deleted. Raises IntegrityError if the
    message id is taken.
    """
    message = Message(
        message_id=message_data["message_id"],
        channel=channel,
        content=message_data["content"],
        direction=MessageDirection.MOBILE,
        version=message_data["version"],
        rich_text=message_data.get("rich_text"),
        format=message_data.get("format"),
        expires_at=message_data["expires_at"],
    )
    attachments = [
        MessageAttachment(
            message=message, name=item["name"], content_type=item["type"], size=item["size"], position=index
        )
        for index, item in enumerate(message_data["attachments"])
    ]
    written = []
    try:
        for index, attachment in enumerate(attachments):
            attachment.file.save(attachment.name, files[attachment_part_name(index)], save=False)
            written.append(attachment.file.name)
        with transaction.atomic():
            message.save(force_insert=True)
            MessageAttachment.objects.bulk_create(attachments)
    except Exception:
        for name in written:
            try:
                message_attachment_storage.delete(name)
            except Exception as e:
                sentry_sdk.capture_exception(e)
        raise
    return message
