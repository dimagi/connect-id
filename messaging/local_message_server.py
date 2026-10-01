"""A stand-in for an external message server (OCS, HQ), for testing messaging against a local PersonalID.

Run it with ``manage.py local_message_server``. It behaves as a real sender does, and only talks to
PersonalID over HTTP, as a real sender would:

- creates channels for users with ``POST /messaging/create_channel/``
- serves the channel key to the phone from ``key_url``, after checking the phone's bearer token
  with PersonalID's userinfo endpoint, exactly as OCS does
- sends encrypted messages with ``POST /messaging/send_fcm/`` (today's plain-text format)
- receives the phone's replies, consent changes and delivery receipts on ``delivery_url``,
  ``consent_url`` and ``callback_url``, verifying PersonalID's HMAC header with the same code
  PersonalID uses to produce it

The only things it does through Django are the one-time setup rows (the Android app's OAuth
application and its own message server record) and listing users to pick a recipient.

Channel keys are kept in a JSON file so the server can hand them to the phone across restarts.
"""

import base64
import hmac
import json
import logging
import os
import threading
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from oauth2_provider.models import Application

from messaging.models import MessageServer
from messaging.tasks import MAC_DIGEST_HEADER, mac_digest
from users.const import TEST_NUMBER_PREFIX
from users.models import ConnectUser, ServerKeys

logger = logging.getLogger(__name__)

# The OAuth client id compiled into the CommCare Android app for PersonalID token requests
# (ApiPersonalId.CONNECT_CLIENT_ID). Production holds the matching Application row; a local
# database needs one too before a phone can fetch a channel key.
ANDROID_CLIENT_ID = "zqFUtAAMrxmjnC1Ji74KAa6ZpY1mZly0J0PlalIa"
ANDROID_APP_NAME = "CommCare Android (local)"

SERVER_NAME = "Local message server"
CHANNEL_SOURCE = "local-message-server"
DEFAULT_STATE_FILE = settings.BASE_DIR / ".local_temp_state" / "local_message_server.json"

GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
REQUEST_TIMEOUT = 10


def log(message):
    print(f"{datetime.now(UTC):%H:%M:%S} {message}", flush=True)


# --- setup rows, through Django ---------------------------------------------------------------


def ensure_android_oauth_application():
    """The Application the phone uses for its password-grant token request. Returns (app, created)."""
    return Application.objects.get_or_create(
        client_id=ANDROID_CLIENT_ID,
        defaults={
            "name": ANDROID_APP_NAME,
            "client_type": Application.CLIENT_PUBLIC,
            "authorization_grant_type": Application.GRANT_PASSWORD,
            # The app asks for the openid scope, which makes the token endpoint sign an id token.
            # HS256 signs with the application's own secret, so no RSA key is needed locally.
            "algorithm": Application.HS256_ALGORITHM,
            "redirect_uris": "",
        },
    )


def ensure_message_server(public_url):
    """This server's MessageServer row, with its callback URLs pointing at public_url. Returns (server, created)."""
    keys, _ = ServerKeys.objects.get_or_create(name=SERVER_NAME)
    public_url = public_url.rstrip("/")
    return MessageServer.objects.update_or_create(
        name=SERVER_NAME,
        defaults={
            "key_url": f"{public_url}/key",
            "callback_url": f"{public_url}/callback",
            "delivery_url": f"{public_url}/delivery",
            "consent_url": f"{public_url}/consent",
            "server_credentials": keys,
        },
    )


def list_users():
    """Active users, demo users first, as (username, phone, name, is_demo) tuples."""
    users = ConnectUser.objects.filter(is_active=True).order_by("date_joined")
    rows = [
        (user.username, str(user.phone_number), user.name, str(user.phone_number).startswith(TEST_NUMBER_PREFIX))
        for user in users
    ]
    return sorted(rows, key=lambda row: not row[3])


# --- crypto, the same scheme the real senders use ---------------------------------------------


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


def new_channel_key():
    return base64.b64encode(os.urandom(32)).decode()


# --- state -------------------------------------------------------------------------------------


class State:
    """Channels this server has created, with the key for each. Persisted between runs."""

    def __init__(self, path=DEFAULT_STATE_FILE):
        self.path = Path(path)
        self.channels = {}
        self.last = None
        self.reload()

    def reload(self):
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


# --- the sender ----------------------------------------------------------------------------------


class Sender:
    """What an external message server does: talks to PersonalID over HTTP with its server credentials."""

    def __init__(self, personalid_url, credentials, state):
        self.personalid_url = personalid_url.rstrip("/")
        self.auth = (credentials.client_id, credentials.secret_key)
        self.secret = credentials.secret_key
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
            channel_id, {"connectid": connectid, "name": name or CHANNEL_SOURCE, "key": new_channel_key()}
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

    def verify_mac(self, body, digest_header):
        """PersonalID signs what it posts to us with our secret; check it with the same code it uses."""
        return hmac.compare_digest(mac_digest(self.secret, body), digest_header or "")

    def username_for_token(self, authorization):
        """Ask PersonalID who the phone's bearer token belongs to. None if it is not accepted."""
        response = requests.get(
            f"{self.personalid_url}/o/userinfo/", headers={"Authorization": authorization}, timeout=REQUEST_TIMEOUT
        )
        if response.status_code != 200:
            return None
        return response.json().get("sub")

    # Endpoint handlers. Each returns (status, payload).

    def serve_key(self, form, authorization):
        channel_id = form.get("channel_id", [None])[0]
        if not channel_id or not authorization:
            return 400, {"error": "channel_id and Authorization are required"}
        self.state.reload()
        channel = self.state.channels.get(channel_id)
        if channel is None:
            return 404, {"error": "unknown channel"}
        username = self.username_for_token(authorization)
        if username is None or username.lower() != channel["connectid"].lower():
            log(f"key refused for channel {channel_id}: token is for {username!r}, not {channel['connectid']!r}")
            return 401, {"error": "token does not match channel"}
        log(f"key served for channel {channel_id} to {username}")
        return 200, {"key": channel["key"]}

    def receive(self, path, body, digest_header):
        if not self.verify_mac(body, digest_header):
            log(f"{path}: bad or missing {MAC_DIGEST_HEADER}, rejected")
            return 401, {"error": "bad signature"}
        data = json.loads(body)
        channel_id = data.get("channel_id")
        self.state.reload()
        if path == "/delivery":
            key = self.state.channels.get(channel_id, {}).get("key")
            for message in data.get("messages", []):
                text = decrypt(key, message) if key else "<no key for this channel>"
                log(f"reply on channel {channel_id} ({message.get('message_id')}): {text}")
        elif path == "/consent":
            log(f"consent on channel {channel_id} is now {data.get('consent')}")
            if channel_id in self.state.channels:
                self.state.channels[channel_id]["consent"] = data.get("consent")
                self.state.save()
        else:
            ids = [m.get("message_id") for m in data.get("messages", [])]
            log(f"delivery receipt on channel {channel_id} for {ids}")
        return 200, {}


class Handler(BaseHTTPRequestHandler):
    sender: Sender

    def log_message(self, format, *args):
        pass  # log() covers what matters

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            if self.path == "/key":
                status, payload = self.sender.serve_key(parse_qs(body.decode()), self.headers.get("Authorization"))
            elif self.path in ("/delivery", "/consent", "/callback"):
                status, payload = self.sender.receive(self.path, body, self.headers.get(MAC_DIGEST_HEADER))
            else:
                status, payload = 404, {"error": "no such endpoint"}
        except Exception as e:
            log(f"error handling {self.path}: {e!r}")
            status, payload = 500, {"error": str(e)}
        self.reply(status, payload)

    def reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_http_server(sender, host, port):
    handler = type("BoundHandler", (Handler,), {"sender": sender})
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --- the prompt ----------------------------------------------------------------------------------

HELP = (
    "commands: users | channel <username> [display name] | send <channel id|last> <text> | list | quit\n"
    "  <username> is the PersonalID username, e.g. 2c69ea9b8272348677d6"
)


def print_users(write):
    rows = list_users()
    if not rows:
        write(f"No users yet. Register one from the app; demo numbers start with {TEST_NUMBER_PREFIX}.")
        return
    write("Users (demo users first):")
    for username, phone, name, is_demo in rows:
        write(f"  {username}  {phone}  {name}{'  (demo)' if is_demo else ''}")


def prompt_loop(sender, write=print):
    write(HELP)
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not line:
            continue
        command, _, rest = line.partition(" ")
        try:
            if command == "users":
                print_users(write)
            elif command == "channel":
                connectid, _, name = rest.partition(" ")
                sender.create_channel(connectid, name or None)
            elif command == "send":
                channel_ref, _, text = rest.partition(" ")
                sender.send_text(channel_ref, text)
            elif command == "list":
                for channel_id, channel in sender.state.channels.items():
                    marker = " (last)" if channel_id == sender.state.last else ""
                    write(f"{channel_id}  {channel['connectid']}  consent={channel.get('consent')}{marker}")
            elif command in ("quit", "exit"):
                return
            else:
                write(HELP)
        except (requests.RequestException, KeyError) as e:
            log(f"{command} failed: {e}")
