from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from messaging import local_message_server as lms


class Command(BaseCommand):
    help = (
        "Run a stand-in for an external message server (OCS, HQ) against this PersonalID, for testing "
        "messaging with a phone. Sets up the Android app's OAuth application and its own message server "
        "record, lists users, then serves the channel key and takes messages at an interactive prompt. "
        "DEBUG only."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--personalid-url",
            default="http://localhost:8000",
            help="Where this process reaches PersonalID (default: %(default)s)",
        )
        parser.add_argument(
            "--listen",
            default="0.0.0.0:8001",
            help="host:port this server listens on (default: %(default)s)",
        )
        parser.add_argument(
            "--public-url",
            default="http://localhost:8001",
            help="How the phone and PersonalID reach this server; stored as the message server's URLs "
            "(default: %(default)s). Use the laptop's LAN address when the phone is not using adb reverse.",
        )
        parser.add_argument(
            "--state-file",
            default=str(lms.DEFAULT_STATE_FILE),
            help="Where channel keys are kept between runs (default: %(default)s)",
        )
        parser.add_argument(
            "--setup-only",
            action="store_true",
            help="Create the setup rows and list users, then exit without serving",
        )

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError("local_message_server is for local development only: it requires DEBUG=True")

        _, created = lms.ensure_android_oauth_application()
        self.stdout.write(f"OAuth application for the Android app: {'created' if created else 'already present'}")
        server, created = lms.ensure_message_server(options["public_url"])
        self.stdout.write(f"Message server '{lms.SERVER_NAME}': {'created' if created else 'updated'}")
        self.stdout.write(f"  key_url:      {server.key_url}")
        self.stdout.write(f"  delivery_url: {server.delivery_url}")
        self.stdout.write("")
        lms.print_users(self.stdout.write)

        if options["setup_only"]:
            return

        host, _, port = options["listen"].rpartition(":")
        try:
            port = int(port)
        except ValueError:
            raise CommandError(f"--listen must be host:port, got {options['listen']!r}")

        sender = lms.Sender(options["personalid_url"], server.server_credentials, lms.State(options["state_file"]))
        http_server = lms.start_http_server(sender, host or "0.0.0.0", port)
        self.stdout.write("")
        listen_host = host or "0.0.0.0"
        lms.log(f"listening on {listen_host}:{port}, reachable as {options['public_url']}")
        lms.log(f"PersonalID at {sender.personalid_url}")
        try:
            lms.prompt_loop(sender, self.stdout.write)
        finally:
            http_server.shutdown()
