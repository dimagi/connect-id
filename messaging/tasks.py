import base64
import hashlib
import hmac
import json

import requests

from messaging.models import Message, MessageStatus


def make_request(url: str, json_data: dict, secret: str) -> bool:
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
        return True
    except requests.exceptions.RequestException:
        return False


def send_messages_to_service_and_mark_status(channel_messages,
                                             status_to_be_updated: MessageStatus):
    sent_message_ids = []

    for channel_id, data in channel_messages.items():
        url = data["url"]
        messages = data["messages"]
        client_secret = data["client_secret"]

        response = make_request(
            url=url,
            json_data={
                "channel": channel_id,
                "messages": messages,
            },
            secret=client_secret
        )
        if response:
            sent_message_ids.extend(msg["message_id"] for msg in messages)

    if sent_message_ids:
        Message.objects.filter(message_id__in=sent_message_ids).update(status=status_to_be_updated)
