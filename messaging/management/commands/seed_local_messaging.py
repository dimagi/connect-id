from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from oauth2_provider.models import Application

from messaging.models import MessageServer
from users.const import TEST_NUMBER_PREFIX
from users.models import ConnectUser, ServerKeys

# The OAuth client id compiled into the CommCare Android app for PersonalID token requests
# (ApiPersonalId.CONNECT_CLIENT_ID). Production holds the matching Application row; a local
# database needs one too before a phone can fetch a channel key.
ANDROID_CLIENT_ID = "zqFUtAAMrxmjnC1Ji74KAa6ZpY1mZly0J0PlalIa"
ANDROID_APP_NAME = "CommCare Android (local)"

LOCAL_SENDER_NAME = "Local sender"


class Command(BaseCommand):
    help = (
        "Create what a phone and scripts/local_sender.py need to exchange messages with this local "
        "PersonalID: the Android app's OAuth application, and a message server for the sender script. "
        "Safe to re-run. Requires LOCAL_MODE."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--sender-url",
            default="http://localhost:8001",
            help="Base URL the phone and this server will reach scripts/local_sender.py on (default: %(default)s)",
        )

    def handle(self, *args, **options):
        if not settings.LOCAL_MODE:
            raise CommandError("seed_local_messaging is for local development only: set LOCAL_MODE=True")

        sender_url = options["sender_url"].rstrip("/")

        _, created = Application.objects.get_or_create(
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
        self.stdout.write(f"OAuth application for the Android app: {'created' if created else 'already present'}")

        keys, _ = ServerKeys.objects.get_or_create(name=LOCAL_SENDER_NAME)
        server, created = MessageServer.objects.update_or_create(
            name=LOCAL_SENDER_NAME,
            defaults={
                "key_url": f"{sender_url}/key",
                "callback_url": f"{sender_url}/callback",
                "delivery_url": f"{sender_url}/delivery",
                "consent_url": f"{sender_url}/consent",
                "server_credentials": keys,
            },
        )
        self.stdout.write(f"Message server '{LOCAL_SENDER_NAME}': {'created' if created else 'updated'}")
        self.stdout.write(f"  key_url:      {server.key_url}")
        self.stdout.write(f"  delivery_url: {server.delivery_url}")
        self.stdout.write("")
        self.stdout.write("Run the sender with:")
        self.stdout.write(
            f"  python scripts/local_sender.py --client-id {keys.client_id} --secret {keys.secret_key} serve"
        )

        demo_users = ConnectUser.objects.filter(phone_number__startswith=TEST_NUMBER_PREFIX, is_active=True).order_by(
            "date_joined"
        )
        self.stdout.write("")
        if demo_users:
            self.stdout.write("Registered demo users (use the username with the sender's `channel` command):")
            for user in demo_users:
                self.stdout.write(f"  {user.username}  {user.phone_number}  {user.name}")
        else:
            self.stdout.write(
                f"No demo users yet. Register one from the app with a phone number starting {TEST_NUMBER_PREFIX}."
            )
