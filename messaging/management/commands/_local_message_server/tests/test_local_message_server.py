import json
from io import StringIO
from unittest import mock

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from oauth2_provider.models import Application

from messaging.management.commands._local_message_server import server as lms
from messaging.models import MessageServer
from messaging.tasks import mac_digest
from users.factories import UserFactory


def run(**options):
    out = StringIO()
    call_command("local_message_server", setup_only=True, stdout=out, **options)
    return out.getvalue()


@pytest.mark.django_db
def test_refuses_without_debug(settings):
    settings.DEBUG = False
    with pytest.raises(CommandError):
        run()


@pytest.mark.django_db
def test_setup_creates_the_app_and_a_server_and_is_idempotent(settings):
    settings.DEBUG = True

    run(public_url="http://sender.test:9000/")
    run(public_url="http://sender.test:9000/")

    app = Application.objects.get(client_id=lms.ANDROID_CLIENT_ID)
    assert app.client_type == Application.CLIENT_PUBLIC
    assert app.authorization_grant_type == Application.GRANT_PASSWORD
    assert app.algorithm == Application.HS256_ALGORITHM

    server = MessageServer.objects.get(name=lms.SERVER_NAME)
    assert server.key_url == "http://sender.test:9000/key"
    assert server.delivery_url == "http://sender.test:9000/delivery"
    assert server.server_credentials is not None
    assert MessageServer.objects.filter(name=lms.SERVER_NAME).count() == 1


@pytest.mark.django_db
def test_lists_users_with_demo_users_first(settings):
    settings.DEBUG = True
    regular = UserFactory(phone_number="+12025550100")
    demo = UserFactory(phone_number="+74261234567", name="Demo Person")

    output = run()

    assert output.index(demo.username) < output.index(regular.username)
    assert f"{demo.username}  *******rson" in output
    assert "4567" not in output
    assert "Demo Person" not in output
    assert output.count("(demo)") == 1


@pytest.mark.parametrize(
    "value, expected",
    [
        ("+99991234567", "********4567"),
        ("John Smith", "******mith"),
        ("1234", "****"),
        ("ab", "**"),
        ("", ""),
        (None, ""),
    ],
)
def test_mask_keeps_only_the_last_four_characters(value, expected):
    assert lms.mask(value) == expected


def test_encrypt_round_trips_through_the_relayed_triple():
    key = lms.new_channel_key()
    triple = lms.encrypt(key, "héllo")

    assert set(triple) == {"ciphertext", "tag", "nonce"}
    assert lms.decrypt(key, triple) == "héllo"


@pytest.mark.django_db
def test_inbound_signature_uses_personalid_own_digest(tmp_path):
    credentials = mock.Mock(client_id="id", secret_key="s3cret")
    sender = lms.Sender("http://personalid.test", credentials, lms.State(tmp_path / "state.json"))
    body = json.dumps({"channel_id": "c1", "messages": []}).encode()

    assert sender.verify_mac(body, mac_digest("s3cret", body))
    assert not sender.verify_mac(body, mac_digest("other", body))
    assert not sender.verify_mac(body, None)


@pytest.mark.django_db
def test_key_is_served_only_to_the_channel_owner(tmp_path):
    credentials = mock.Mock(client_id="id", secret_key="s3cret")
    state = lms.State(tmp_path / "state.json")
    state.channels["c1"] = {"connectid": "AbC123", "key": lms.new_channel_key()}
    state.save()
    sender = lms.Sender("http://personalid.test", credentials, state)

    with mock.patch.object(sender, "username_for_token", return_value="abc123"):
        assert sender.serve_key({"channel_id": ["c1"]}, "Bearer t")[0] == 200
    with mock.patch.object(sender, "username_for_token", return_value="someoneelse"):
        assert sender.serve_key({"channel_id": ["c1"]}, "Bearer t")[0] == 401
    with mock.patch.object(sender, "username_for_token", return_value=None):
        assert sender.serve_key({"channel_id": ["c1"]}, "Bearer t")[0] == 401
    assert sender.serve_key({"channel_id": ["nope"]}, "Bearer t")[0] == 404
    assert sender.serve_key({}, None)[0] == 400


@pytest.mark.django_db
def test_user_listing_refuses_without_debug(settings):
    settings.DEBUG = False
    with pytest.raises(RuntimeError):
        lms.print_users(lambda line: None)
