from unittest import mock

import pytest

from utils import get_sms_sender, send_sms


@pytest.mark.parametrize(
    "country_code,expected",
    [
        ("265", "ConnectID"),
        ("258", "ConnectID"),
        ("232", "ConnectID"),
        ("44", "ConnectID"),
        (265, "ConnectID"),  # int is coerced via str()
        ("1", None),
        ("27", None),
    ],
)
def test_get_sms_sender(country_code, expected):
    assert get_sms_sender(country_code) == expected


@mock.patch("utils.Client")
def test_send_sms_invokes_twilio_client(mock_client_cls, settings):
    """Pin the twilio call surface (Client init + messages.create kwargs) so a
    breaking twilio major bump is caught in CI rather than only at runtime."""
    settings.TWILIO_ACCOUNT_SID = "sid"
    settings.TWILIO_AUTH_TOKEN = "token"
    settings.TWILIO_MESSAGING_SERVICE = "MGxxxx"
    messages = mock_client_cls.return_value.messages

    send_sms(to="+265123456", body="test message", sender="ConnectID")

    mock_client_cls.assert_called_once_with("sid", "token")
    messages.create.assert_called_once_with(
        body="test message",
        to="+265123456",
        from_="ConnectID",
        messaging_service_sid="MGxxxx",
    )


@mock.patch("utils.Client")
def test_send_sms_defaults_sender_to_none(mock_client_cls, settings):
    settings.TWILIO_ACCOUNT_SID = "sid"
    settings.TWILIO_AUTH_TOKEN = "token"
    settings.TWILIO_MESSAGING_SERVICE = "MGxxxx"
    messages = mock_client_cls.return_value.messages

    send_sms(to="+15555550123", body="hi")

    assert messages.create.call_args.kwargs["from_"] is None
