from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from oauth2_provider.models import Application

from messaging.management.commands.seed_local_messaging import ANDROID_CLIENT_ID, LOCAL_SENDER_NAME
from messaging.models import MessageServer
from users.factories import UserFactory


def seed(**options):
    out = StringIO()
    call_command("seed_local_messaging", stdout=out, **options)
    return out.getvalue()


@pytest.mark.django_db
def test_refuses_outside_local_mode(settings):
    settings.LOCAL_MODE = False
    with pytest.raises(CommandError):
        seed()


@pytest.mark.django_db
def test_creates_the_app_and_a_sender_and_is_idempotent(settings):
    settings.LOCAL_MODE = True

    output = seed(sender_url="http://sender.test:9000/")
    seed(sender_url="http://sender.test:9000/")

    app = Application.objects.get(client_id=ANDROID_CLIENT_ID)
    assert app.client_type == Application.CLIENT_PUBLIC
    assert app.authorization_grant_type == Application.GRANT_PASSWORD
    assert app.algorithm == Application.HS256_ALGORITHM

    server = MessageServer.objects.get(name=LOCAL_SENDER_NAME)
    assert server.key_url == "http://sender.test:9000/key"
    assert server.delivery_url == "http://sender.test:9000/delivery"
    assert server.server_credentials is not None
    assert MessageServer.objects.filter(name=LOCAL_SENDER_NAME).count() == 1

    assert f"--client-id {server.server_credentials.client_id}" in output
    assert f"--secret {server.server_credentials.secret_key}" in output


@pytest.mark.django_db
def test_lists_demo_users(settings):
    settings.LOCAL_MODE = True
    demo = UserFactory(phone_number="+74261234567")
    UserFactory(phone_number="+12025550100")

    output = seed()

    assert demo.username in output
    assert output.count("  +") == 1
