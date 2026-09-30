#!/usr/bin/env python
"""A stand-in for a message server (OCS, HQ) against a PersonalID running in LOCAL_MODE.

It does what a real sender does, and nothing the real sender does not:

- creates channels for users with ``POST /messaging/create_channel/``
- serves the channel key to the phone from ``key_url``, after checking the phone's bearer
  token with PersonalID's userinfo endpoint, exactly as OCS does
- sends encrypted messages with ``POST /messaging/send_fcm/`` (today's plain-text format)
- receives the phone's replies, consent changes and delivery receipts on ``delivery_url``,
  ``consent_url`` and ``callback_url``, verifying PersonalID's HMAC header

Set the server up once with ``manage.py seed_local_messaging``; it prints the command to run.

    python scripts/local_sender.py --client-id ID --secret SECRET serve

then, at the prompt::

    channel <username> [display name]   create (or fetch) the user's channel
    send <channel id | last> <text>     send a message
    list                                channels this sender knows
    quit

``channel`` and ``send`` also work as one-shot subcommands. Channel keys are kept in
``scripts/.local_temp_state/`` so ``serve`` can hand them to the phone later. Delete that directory to start over.

The phone must be able to reach both servers. With a USB-connected device::

    adb reverse tcp:8000 tcp:8000
    adb reverse tcp:8001 tcp:8001
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STATE_DIR = Path(__file__).with_name(".local_temp_state")
STATE_FILE = STATE_DIR / "local_sender_state.json"
CHANNEL_SOURCE = "local-sender"
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
REQUEST_TIMEOUT = 10


def log(message):
    print(f"{datetime.now(UTC):%H:%M:%S} {message}", flush=True)


class State:
    """Channels this sender has created, with the key for each. Persisted between runs."""

    def __init__(self, path=STATE_FILE):
        self.path = path
        self.channels = {}
        self.last = None
        self.reload()

    def reload(self):
        """Pick up channels created by another process, e.g. a one-shot `channel` command."""
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.channels = data.get("channels", {})
            self.last = data.get("last")

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"channels": self.channels, "last": self.last}, indent=2))

    def resolve(self, channel_ref):
        channel_id = self.last if channel_ref == "last" else channel_ref
        if channel_id not in self.channels:
            raise KeyError(f"unknown channel {channel_ref!r}; run `channel <username>` first")
        return channel_id


def encrypt(key_b64, text):
    """Return the ciphertext, tag and nonce triple PersonalID relays, all base64."""
    key = base64.b64decode(key_b64)
    nonce = os.urandom(GCM_NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    ciphertext, tag = sealed[:-GCM_TAG_BYTES], sealed[-GCM_TAG_BYTES:]
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }


def decrypt(key_b64, message):
    key = base64.b64decode(key_b64)
    sealed = base64.b64decode(message["ciphertext"]) + base64.b64decode(message["tag"])
    return AESGCM(key).decrypt(base64.b64decode(message["nonce"]), sealed, None).decode("utf-8")


class Sender:
    def __init__(self, personalid_url, client_id, secret, state):
        self.personalid_url = personalid_url.rstrip("/")
        self.auth = (client_id, secret)
        self.secret = secret
        self.state = state

    def create_channel(self, connectid, name=None):
        payload = {"connectid": connectid, "channel_source": CHANNEL_SOURCE}
        if name:
            payload["channel_name"] = name
        response = requests.post(
            f"{self.personalid_url}/messaging/create_channel/", json=payload, auth=self.auth, timeout=REQUEST_TIMEOUT
        )
        if response.status_code not in (200, 201):
            log(f"create_channel for {connectid!r} failed: {response.status_code} {response.text}")
            return None
        data = response.json()
        channel_id = data["channel_id"]
        channel = self.state.channels.setdefault(
            channel_id,
            {"connectid": connectid, "name": name or CHANNEL_SOURCE, "key": base64.b64encode(os.urandom(32)).decode()},
        )
        channel["consent"] = data["consent"]
        self.state.last = channel_id
        self.state.save()
        verb = "created" if response.status_code == 201 else "already existed"
        log(f"channel {channel_id} for {connectid} {verb}, consent={data['consent']}")
        return channel_id

    def send_text(self, channel_ref, text):
        channel_id = self.state.resolve(channel_ref)
        message_id = str(uuid.uuid4())
        payload = {
            "channel": channel_id,
            "message_id": message_id,
            "content": encrypt(self.state.channels[channel_id]["key"], text),
        }
        response = requests.post(
            f"{self.personalid_url}/messaging/send_fcm/", json=payload, auth=self.auth, timeout=REQUEST_TIMEOUT
        )
        if response.status_code != 200:
            log(f"send failed: {response.status_code} {response.text}")
            return None
        log(f"sent {message_id} to channel {channel_id}")
        return message_id

    def verify_hmac(self, body, digest_header):
        expected = base64.b64encode(hmac.new(self.secret.encode(), body, hashlib.sha256).digest()).decode()
        return hmac.compare_digest(expected, digest_header or "")

    def username_for_token(self, authorization):
        """Ask PersonalID who the phone's bearer token belongs to. None if it is not accepted."""
        response = requests.get(
            f"{self.personalid_url}/o/userinfo/", headers={"Authorization": authorization}, timeout=REQUEST_TIMEOUT
        )
        if response.status_code != 200:
            return None
        return response.json().get("sub")


class Handler(BaseHTTPRequestHandler):
    sender: Sender

    def log_message(self, format, *args):
        pass  # our own log() is enough

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.sender.state.reload()
        try:
            if self.path == "/key":
                self.serve_key(body)
            elif self.path in ("/delivery", "/consent", "/callback"):
                self.receive_from_personalid(body)
            else:
                self.reply(404, {"error": "no such endpoint"})
        except Exception as e:
            log(f"error handling {self.path}: {e!r}")
            self.reply(500, {"error": str(e)})

    def serve_key(self, body):
        form = parse_qs(body.decode())
        channel_id = form.get("channel_id", [None])[0]
        authorization = self.headers.get("Authorization")
        if not channel_id or not authorization:
            return self.reply(400, {"error": "channel_id and Authorization are required"})
        channel = self.sender.state.channels.get(channel_id)
        if channel is None:
            return self.reply(404, {"error": "unknown channel"})
        username = self.sender.username_for_token(authorization)
        if username is None or username.lower() != channel["connectid"].lower():
            log(f"key refused for channel {channel_id}: token is for {username!r}, not {channel['connectid']!r}")
            return self.reply(401, {"error": "token does not match channel"})
        log(f"key served for channel {channel_id} to {username}")
        self.reply(200, {"key": channel["key"]})

    def receive_from_personalid(self, body):
        if not self.sender.verify_hmac(body, self.headers.get("X-MAC-DIGEST")):
            log(f"{self.path}: bad or missing X-MAC-DIGEST, rejected")
            return self.reply(401, {"error": "bad signature"})
        data = json.loads(body)
        channel_id = data.get("channel_id")
        if self.path == "/delivery":
            key = self.sender.state.channels.get(channel_id, {}).get("key")
            for message in data.get("messages", []):
                text = decrypt(key, message) if key else "<no key for this channel>"
                log(f"reply on channel {channel_id} ({message.get('message_id')}): {text}")
        elif self.path == "/consent":
            log(f"consent on channel {channel_id} is now {data.get('consent')}")
            if channel_id in self.sender.state.channels:
                self.sender.state.channels[channel_id]["consent"] = data.get("consent")
                self.sender.state.save()
        else:
            ids = [m.get("message_id") for m in data.get("messages", [])]
            log(f"delivery receipt on channel {channel_id} for {ids}")
        self.reply(200, {})

    def reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def prompt_loop(sender):
    print(
        "commands: channel <personalid username, e.g. 2c69ea9b8272348677d6> [display name] | "
        "send <channel id|last> <text> | list | quit",
        flush=True,
    )
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not line:
            continue
        command, _, rest = line.partition(" ")
        try:
            if command == "channel":
                connectid, _, name = rest.partition(" ")
                sender.create_channel(connectid, name or None)
            elif command == "send":
                channel_ref, _, text = rest.partition(" ")
                sender.send_text(channel_ref, text)
            elif command == "list":
                for channel_id, channel in sender.state.channels.items():
                    marker = " (last)" if channel_id == sender.state.last else ""
                    print(f"{channel_id}  {channel['connectid']}  consent={channel.get('consent')}{marker}")
            elif command in ("quit", "exit"):
                return
            else:
                print("unknown command")
        except (requests.RequestException, KeyError) as e:
            log(f"{command} failed: {e}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--personalid", default="http://localhost:8000", help="PersonalID base URL")
    parser.add_argument("--client-id", default=os.environ.get("LOCAL_SENDER_CLIENT_ID"), required=False)
    parser.add_argument("--secret", default=os.environ.get("LOCAL_SENDER_SECRET"), required=False)
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="listen for the phone and PersonalID, with an interactive prompt")
    serve.add_argument("--port", type=int, default=8001)

    channel = subparsers.add_parser("channel", help="create (or fetch) a user's channel")
    channel.add_argument("connectid")
    channel.add_argument("--name")

    send = subparsers.add_parser("send", help="send a message")
    send.add_argument("channel", help="channel id, or `last`")
    send.add_argument("text")

    args = parser.parse_args()
    if not (args.client_id and args.secret):
        parser.error("--client-id and --secret are required (or LOCAL_SENDER_CLIENT_ID / LOCAL_SENDER_SECRET)")

    sender = Sender(args.personalid, args.client_id, args.secret, State())

    if args.command == "channel":
        sender.create_channel(args.connectid, args.name)
    elif args.command == "send":
        sender.send_text(args.channel, args.text)
    else:
        Handler.sender = sender
        server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        log(f"listening on port {args.port}; PersonalID at {sender.personalid_url}")
        try:
            prompt_loop(sender)
        finally:
            server.shutdown()


if __name__ == "__main__":
    sys.exit(main())
