from unittest import mock

import pytest
from phonenumber_field.phonenumber import to_python

from sms import SmsCountryNotSupportedError, SmsRateLimitedError, send_sms
from sms.base import SendResult, SmsMessage
from users.const import TEST_NUMBER_PREFIX


@pytest.fixture
def get_vendor():
    with mock.patch("sms.get_vendor") as get_vendor:
        yield get_vendor


def test_sends_via_the_configured_vendor(get_vendor, settings):
    settings.SMS_DEFAULT_VENDOR = "twilio"
    get_vendor.return_value.send.return_value = SendResult(vendor="twilio", vendor_message_id="SM123")
    to = to_python("+265991234567")

    result = send_sms(to, "hi")

    get_vendor.assert_called_once_with("twilio")
    get_vendor.return_value.send.assert_called_once_with(SmsMessage(to=to, body="hi"))
    assert result == SendResult(vendor="twilio", vendor_message_id="SM123")


def test_test_numbers_are_skipped_without_building_a_vendor(get_vendor):
    result = send_sms(to_python(TEST_NUMBER_PREFIX + "1234567"), "hi")

    assert result == SendResult(vendor=None, vendor_message_id=None, skipped=True)
    get_vendor.assert_not_called()


def test_unparseable_number_is_not_treated_as_a_test_number(get_vendor, settings):
    settings.SMS_DEFAULT_VENDOR = "twilio"
    settings.SMS_SUPPORTED_COUNTRY_CODES = []
    send_sms(to_python("garbage"), "hi")

    get_vendor.assert_called_once_with("twilio")


def test_console_vendor_logs_instead_of_sending(settings, caplog):
    settings.SMS_DEFAULT_VENDOR = "console"
    to = to_python("+265991234567")

    with caplog.at_level("INFO", logger="sms.vendors.console"):
        result = send_sms(to, "Your code is 123456")

    assert result == SendResult(vendor="console", vendor_message_id=None)
    assert "Your code is 123456" in caplog.text


def test_number_outside_supported_countries_is_not_sent(get_vendor, settings):
    settings.SMS_SUPPORTED_COUNTRY_CODES = ["265"]

    with pytest.raises(SmsCountryNotSupportedError):
        send_sms(to_python("+258821234567"), "hi")

    get_vendor.assert_not_called()


def test_number_in_supported_countries_is_sent(get_vendor, settings):
    settings.SMS_SUPPORTED_COUNTRY_CODES = ["265"]

    send_sms(to_python("+265991234567"), "hi")

    get_vendor.return_value.send.assert_called_once()


def test_sends_to_one_number_are_capped(get_vendor, settings):
    settings.SMS_NUMBER_HOURLY_LIMIT = 2
    to = to_python("+265991234567")
    send_sms(to, "hi")
    send_sms(to, "hi")

    with pytest.raises(SmsRateLimitedError) as exc_info:
        send_sms(to, "hi")

    assert exc_info.value.retry_after_seconds > 0
    assert get_vendor.return_value.send.call_count == 2


def test_sends_to_one_country_are_capped_and_reported_once(get_vendor, settings, caplog):
    settings.PHONE_COUNTRY_HOURLY_LIMIT = 1
    send_sms(to_python("+265991234567"), "hi")

    for number in ["+265991234568", "+265991234569"]:
        with pytest.raises(SmsRateLimitedError):
            send_sms(to_python(number), "hi")
    send_sms(to_python("+258821234567"), "hi")

    assert get_vendor.return_value.send.call_count == 2
    reports = [r for r in caplog.records if r.levelname == "ERROR" and "country code 265" in r.getMessage()]
    assert len(reports) == 1


def test_test_numbers_are_not_limited(get_vendor, settings):
    settings.SMS_SUPPORTED_COUNTRY_CODES = ["265"]
    settings.PHONE_COUNTRY_HOURLY_LIMIT = 0

    result = send_sms(to_python(TEST_NUMBER_PREFIX + "1234567"), "hi")

    assert result.skipped
