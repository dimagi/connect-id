"""Receiving messages on create_message: text, optional encrypted attachments, one multipart request.

The request has a "message" part holding JSON (see CreateMessageSerializer) and one part per
attachment, named attachment_0, attachment_1, ... in the order of the "attachments" list. The
part's own filename is ignored; the JSON's "name" is the attachment's name.

The caller sends its text once, in "content". PersonalID decides what the device gets:

- No "content_legacy_msg": the device's "content" is the caller's text, and there is no "rich_text".
- With "content_legacy_msg": the device's "content" is the legacy message, which is all that apps
  unable to show rich messages display, and "rich_text" is the caller's text, or "" when the caller
  sent none (a message that is only attachments). Apps that can show rich messages show "rich_text"
  whenever it is present.

Both texts are encrypted by the caller with the channel key. PersonalID only decides where each one
goes; it cannot read or write them.
"""

import json

import sentry_sdk
from django.db import transaction
from django.utils.timezone import now
from rest_framework import status

from messaging.const import (
    DEFAULT_ATTACHMENT_FORMAT,
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS_PER_MESSAGE,
    MAX_MESSAGE_ATTACHMENT_BYTES,
    MAX_RICH_REQUEST_OVERHEAD_BYTES,
    MESSAGING_VERSION,
    MESSAGING_VERSION_HEADER,
    ErrorCodes,
)
from messaging.models import Message, MessageAttachment, MessageDirection
from messaging.serializers import CreateMessageSerializer
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


def check_caller_version(headers):
    """Refuse a caller written for a newer message format than this server supports.

    The header is optional and only tests compatibility; it does not choose the format the device
    gets. Absent means the caller accepts whatever this server supports.
    """
    declared = headers.get(MESSAGING_VERSION_HEADER)
    if declared is None:
        return
    try:
        version = int(declared)
    except ValueError:
        raise RichMessageRejected(ErrorCodes.UNSUPPORTED_VERSION)
    if not 1 <= version <= MESSAGING_VERSION:
        raise RichMessageRejected(ErrorCodes.UNSUPPORTED_VERSION)


def parse_message_request(data, files):
    """Validate the JSON part against the uploaded parts. Returns the validated message."""
    raw = data.get("message")
    if not isinstance(raw, str):
        raise RichMessageRejected(ErrorCodes.INVALID_MESSAGE, detail={"message": "Missing JSON part."})
    try:
        payload = json.loads(raw)
    except ValueError:
        raise RichMessageRejected(ErrorCodes.INVALID_MESSAGE, detail={"message": "Not valid JSON."})
    if not isinstance(payload, dict):
        raise RichMessageRejected(ErrorCodes.INVALID_MESSAGE, detail={"message": "Not a JSON object."})
    # An empty content is sent as "" or null, or left out; all three mean the same
    if payload.get("content") in ("", None):
        payload.pop("content", None)

    serializer = CreateMessageSerializer(data=payload)
    if not serializer.is_valid():
        raise RichMessageRejected(ErrorCodes.INVALID_MESSAGE, detail=serializer.errors)
    message = serializer.validated_data
    attachments = message["attachments"]

    if "content" not in message:
        if not attachments:
            raise RichMessageRejected(ErrorCodes.INVALID_MESSAGE_CONTENT)
        if "content_legacy_msg" not in message:
            raise RichMessageRejected(ErrorCodes.CONTENT_LEGACY_MSG_REQUIRED)

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

    # Optional for every message, with no default and no upper limit for now
    expires_at = message.get("expires_at")
    if expires_at is not None and expires_at <= now():
        raise RichMessageRejected(ErrorCodes.INVALID_EXPIRY)
    return message


def store_message(channel, message_data, files):
    """Write the attachment files, then the message and attachment rows in one transaction.

    Message.content and Message.rich_text hold what the device gets (see the module docstring).
    Files are written before the transaction so it is not held open during uploads to storage. If
    anything fails afterwards, the files already written are deleted. Raises IntegrityError if the
    message id is taken.
    """
    if "content_legacy_msg" in message_data:
        content, rich_text = message_data["content_legacy_msg"], message_data.get("content", "")
    else:
        content, rich_text = message_data["content"], None
    message_format = message_data.get("format")
    if message_format is None and message_data["attachments"]:
        message_format = DEFAULT_ATTACHMENT_FORMAT
    message = Message(
        message_id=message_data["message_id"],
        channel=channel,
        content=content,
        direction=MessageDirection.MOBILE,
        version=MESSAGING_VERSION,
        rich_text=rich_text,
        format=message_format,
        expires_at=message_data.get("expires_at"),
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
