import base64
import hashlib
import hmac
import json

import requests
from rest_framework import status
from rest_framework.generics import get_object_or_404

from messaging.models import Message, MessageStatus, Channel


class CommCareHQAPIException(Exception):
    pass


def make_request(url, json_data, secret):
    try:
        data = json.dumps(json_data).encode('utf-8')
        digest = hmac.new(secret.encode('utf-8'), data, hashlib.sha256).digest()
        mac_digest = base64.b64encode(digest).decode('utf-8')
        headers = {
            "Content-Type": "application/json",
            "X-MAC-DIGEST": mac_digest,
        }
        response = requests.post(url, json=json_data, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        return CommCareHQAPIException({"status": "error", "message": str(e)})


def send_messages_to_service_and_mark_status(channel_messages,
                                             status_to_be_updated: MessageStatus):
    sent_message_ids = []

    for channel_id, data in channel_messages.items():
        url = data["url"]
        messages = data["messages"]

        try:
            channel = get_object_or_404(Channel, channel_id=channel_id)

            response = make_request(
                url=url,
                json_data={
                    "channel": str(channel_id),
                    "messages": messages,
                },
                secret=channel.server.secret_key
            )
            if response == status.HTTP_200_OK:
                sent_message_ids.extend(msg["message_id"] for msg in messages)

        except CommCareHQAPIException as e:
            # To-Do: All the messages which gets failed should be sent again with some task.
            pass

    if sent_message_ids:
        Message.objects.filter(message_id__in=sent_message_ids).update(status=status_to_be_updated)
