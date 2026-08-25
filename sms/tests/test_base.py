import pytest
from phonenumber_field.phonenumber import to_python

from sms.base import BaseSmsVendor, SendResult, SmsMessage, SmsSendError


class Boom(Exception):
    pass


class FakeVendor(BaseSmsVendor):
    name = "fake"

    def __init__(self, raises=None):
        self._raises = raises
        self.sent = []

    def _send(self, message, sender):
        if self._raises:
            raise self._raises
        self.sent.append((message, sender))
        return SendResult(vendor=self.name, vendor_message_id="id-1")


@pytest.fixture
def message():
    return SmsMessage(to=to_python("+265991234567"), body="hi")


def test_send_uses_get_sender_override(message):
    class SenderVendor(FakeVendor):
        def get_sender(self, message):
            return "ConnectID"

    vendor = SenderVendor()
    vendor.send(message)

    assert vendor.sent == [(message, "ConnectID")]


def test_send_wraps_vendor_exceptions(message):
    cause = Boom("network down")

    with pytest.raises(SmsSendError) as excinfo:
        FakeVendor(raises=cause).send(message)

    assert str(excinfo.value) == "fake: network down"
    assert excinfo.value.vendor == "fake"
    assert excinfo.value.vendor_error_code is None
    assert excinfo.value.__cause__ is cause


def test_send_wraps_with_vendor_error_code(message):
    class CodedVendor(FakeVendor):
        def error_code(self, exc):
            return "42"

    with pytest.raises(SmsSendError) as excinfo:
        CodedVendor(raises=Boom("nope")).send(message)

    assert excinfo.value.vendor_error_code == "42"
    # The code is in the message too, so Sentry keeps distinct failures apart.
    assert str(excinfo.value) == "fake [42]: nope"


def test_send_does_not_rewrap_sms_send_error(message):
    original = SmsSendError("fake", "already wrapped", "7")

    with pytest.raises(SmsSendError) as excinfo:
        FakeVendor(raises=original).send(message)

    assert excinfo.value is original


def test_vendor_must_implement_send():
    class Incomplete(BaseSmsVendor):
        name = "incomplete"

    with pytest.raises(TypeError):
        Incomplete()
