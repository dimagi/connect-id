from unittest import mock

import pytest
from phonenumber_field.phonenumber import to_python
from twilio.base.exceptions import TwilioRestException

from sms.base import SendResult, SmsMessage, SmsSendError
from sms.vendors.twilio import TwilioVendor


@pytest.fixture
def vendor():
    with mock.patch("sms.vendors.twilio.Client") as client_cls:
        vendor = TwilioVendor(account_sid="sid", auth_token="token", messaging_service="MGxxxx")
        vendor.client_cls = client_cls
        yield vendor


@pytest.mark.parametrize(
    "number,expected",
    [
        ("+265991234567", "ConnectID"),  # Malawi
        ("+258821234567", "ConnectID"),  # Mozambique
        ("+23276123456", "ConnectID"),  # Sierra Leone
        ("+447400123456", "ConnectID"),  # UK
        ("+12025550123", None),  # no registered sender ID, Twilio picks one
        ("+27821234567", None),
        ("garbage", None),  # unparseable number has no country code
    ],
)
def test_get_sender(vendor, number, expected):
    assert vendor.get_sender(SmsMessage(to=to_python(number), body="hi")) == expected


def test_send_invokes_twilio_client():
    """Pin the twilio call surface (Client init + messages.create kwargs) so a
    breaking twilio major bump is caught in CI rather than only at runtime."""
    with mock.patch("sms.vendors.twilio.Client") as client_cls:
        vendor = TwilioVendor(account_sid="sid", auth_token="token", messaging_service="MGxxxx")
        client_cls.assert_called_once_with("sid", "token")
        messages = client_cls.return_value.messages
        messages.create.return_value.sid = "SM123"

        result = vendor.send(SmsMessage(to=to_python("+265991234567"), body="test message"))

    messages.create.assert_called_once_with(
        body="test message",
        to="+265991234567",
        from_="ConnectID",
        messaging_service_sid="MGxxxx",
    )
    assert result == SendResult(vendor="twilio", vendor_message_id="SM123")


def test_send_omits_sender_when_not_registered(vendor):
    vendor.send(SmsMessage(to=to_python("+12025550123"), body="hi"))

    assert vendor.client_cls.return_value.messages.create.call_args.kwargs["from_"] is None


def test_send_wraps_twilio_error_with_its_code(vendor):
    vendor.client_cls.return_value.messages.create.side_effect = TwilioRestException(
        status=400, uri="/Messages", msg="unsubscribed recipient", code=21610
    )

    with pytest.raises(SmsSendError) as excinfo:
        vendor.send(SmsMessage(to=to_python("+265991234567"), body="hi"))

    assert excinfo.value.vendor == "twilio"
    assert excinfo.value.vendor_error_code == "21610"
    assert "unsubscribed recipient" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, TwilioRestException)


def test_wraps_twilio_error_without_a_code(vendor):
    vendor.client_cls.return_value.messages.create.side_effect = TwilioRestException(
        status=503, uri="/Messages", msg="Service Unavailable"
    )

    with pytest.raises(SmsSendError) as excinfo:
        vendor.send(SmsMessage(to=to_python("+265991234567"), body="hi"))

    assert excinfo.value.vendor_error_code is None


def test_error_code_is_none_for_non_twilio_errors(vendor):
    assert vendor.error_code(ValueError("boom")) is None
