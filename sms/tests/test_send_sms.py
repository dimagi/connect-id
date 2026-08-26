from unittest import mock

import pytest
from phonenumber_field.phonenumber import to_python

from sms import send_sms
from sms.base import SendResult, SmsMessage
from sms.registry import DEFAULT_VENDOR
from users.const import TEST_NUMBER_PREFIX


@pytest.fixture
def get_vendor():
    with mock.patch("sms.get_vendor") as get_vendor:
        yield get_vendor


def test_sends_via_the_default_vendor(get_vendor):
    get_vendor.return_value.send.return_value = SendResult(vendor="twilio", vendor_message_id="SM123")
    to = to_python("+265991234567")

    result = send_sms(to, "hi")

    get_vendor.assert_called_once_with(DEFAULT_VENDOR)
    get_vendor.return_value.send.assert_called_once_with(SmsMessage(to=to, body="hi"))
    assert result == SendResult(vendor="twilio", vendor_message_id="SM123")


def test_test_numbers_are_skipped_without_building_a_vendor(get_vendor):
    result = send_sms(to_python(TEST_NUMBER_PREFIX + "1234567"), "hi")

    assert result == SendResult(vendor=None, vendor_message_id=None, skipped=True)
    get_vendor.assert_not_called()


def test_unparseable_number_is_not_treated_as_a_test_number(get_vendor):
    send_sms(to_python("garbage"), "hi")

    get_vendor.assert_called_once_with(DEFAULT_VENDOR)
