from unittest import mock

import pytest
from phonenumber_field.phonenumber import to_python

from sms import SmsCountryNotSupportedError, SmsRateLimitedError, send_sms
from sms.base import SendResult, SmsMessage
from sms.limits import mask
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


def test_unparseable_number_is_not_treated_as_a_test_number(get_vendor, settings, config):
    settings.SMS_DEFAULT_VENDOR = "twilio"
    config.SMS_SUPPORTED_COUNTRY_CODES = ""
    send_sms(to_python("garbage"), "hi")

    get_vendor.assert_called_once_with("twilio")


def test_console_vendor_logs_instead_of_sending(settings, caplog):
    settings.SMS_DEFAULT_VENDOR = "console"
    to = to_python("+265991234567")

    with caplog.at_level("INFO", logger="sms.vendors.console"):
        result = send_sms(to, "Your code is 123456")

    assert result == SendResult(vendor="console", vendor_message_id=None)
    assert "Your code is 123456" in caplog.text


def test_number_outside_supported_countries_is_not_sent(get_vendor, config):
    config.SMS_SUPPORTED_COUNTRY_CODES = "265"

    with pytest.raises(SmsCountryNotSupportedError):
        send_sms(to_python("+258821234567"), "hi")

    get_vendor.assert_not_called()


def test_number_in_supported_countries_is_sent(get_vendor, config):
    config.SMS_SUPPORTED_COUNTRY_CODES = "265"

    send_sms(to_python("+265991234567"), "hi")

    get_vendor.return_value.send.assert_called_once()


def test_supported_country_codes_may_have_spaces(get_vendor, config):
    config.SMS_SUPPORTED_COUNTRY_CODES = "265, 258"

    send_sms(to_python("+258821234567"), "hi")

    get_vendor.return_value.send.assert_called_once()


def test_sends_to_one_number_are_capped(get_vendor, config):
    config.SMS_NUMBER_HOURLY_LIMIT = 2
    to = to_python("+265991234567")
    send_sms(to, "hi")
    send_sms(to, "hi")

    with pytest.raises(SmsRateLimitedError) as exc_info:
        send_sms(to, "hi")

    assert exc_info.value.retry_after_seconds > 0
    assert get_vendor.return_value.send.call_count == 2


def test_sends_to_one_country_are_capped_and_reported_once(get_vendor, config, caplog):
    config.PHONE_COUNTRY_HOURLY_LIMIT = 1
    send_sms(to_python("+265991234567"), "hi")

    for number in ["+265991234568", "+265991234569"]:
        with pytest.raises(SmsRateLimitedError):
            send_sms(to_python(number), "hi")
    send_sms(to_python("+258821234567"), "hi")

    assert get_vendor.return_value.send.call_count == 2
    reports = [r for r in caplog.records if r.levelname == "ERROR"]
    assert [r.getMessage() for r in reports] == [
        "rate_limit_reached scope=sms kind=country country_code=265 window_seconds=3600 max_count=1"
    ]
    blocks = [r for r in caplog.records if r.getMessage().startswith("rate_limit_blocked scope=sms kind=country")]
    assert len(blocks) == 2


def test_nearing_a_country_limit_is_reported_once(get_vendor, config, caplog):
    config.PHONE_COUNTRY_HOURLY_LIMIT = 5
    config.RATE_LIMIT_WARN_FRACTION = 0.6
    for number in ["+265991234561", "+265991234562", "+265991234563", "+265991234564"]:
        send_sms(to_python(number), "hi")

    reports = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert reports == [
        "rate_limit_approaching scope=sms kind=country country_code=265 window_seconds=3600 max_count=5 count=3"
    ]


def test_blocks_on_one_number_are_logged_without_the_number(get_vendor, config, caplog):
    config.SMS_NUMBER_HOURLY_LIMIT = 1
    to = to_python("+265991234567")
    send_sms(to, "hi")

    with pytest.raises(SmsRateLimitedError):
        send_sms(to, "hi")

    (block,) = (r for r in caplog.records if r.getMessage().startswith("rate_limit_blocked"))
    assert block.levelname == "WARNING"
    assert (
        "kind=number country_code=265 number_ending=567 window_seconds=3600 max_count=1 count=2" in block.getMessage()
    )
    assert "991234567" not in caplog.text


def test_test_numbers_are_not_limited(get_vendor, config):
    config.SMS_SUPPORTED_COUNTRY_CODES = "265"
    config.PHONE_COUNTRY_HOURLY_LIMIT = 0

    result = send_sms(to_python(TEST_NUMBER_PREFIX + "1234567"), "hi")

    assert result.skipped


def test_mask_keeps_the_country_and_last_three_digits():
    assert mask(to_python("+265991234567")) == "+265 …567"
    assert mask(to_python("garbage")) == "an unparseable number"
