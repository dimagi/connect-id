from unittest import mock

import pytest
from django.core.exceptions import ImproperlyConfigured

from sms.registry import DEFAULT_VENDOR, get_vendor
from sms.vendors.twilio import TwilioVendor


def test_builds_vendor_from_settings(settings):
    settings.SMS_VENDORS = {"twilio": {"account_sid": "sid", "auth_token": "token", "messaging_service": "MGxxxx"}}

    with mock.patch("sms.vendors.twilio.Client") as client_cls:
        vendor = get_vendor("twilio")

    assert isinstance(vendor, TwilioVendor)
    client_cls.assert_called_once_with("sid", "token")


def test_default_vendor_is_registered(settings):
    with mock.patch("sms.vendors.twilio.Client"):
        assert get_vendor(DEFAULT_VENDOR).name == DEFAULT_VENDOR


def test_unknown_vendor(settings):
    with pytest.raises(ImproperlyConfigured, match="Unknown SMS vendor 'carrier-pigeon'"):
        get_vendor("carrier-pigeon")


def test_vendor_without_settings_entry(settings):
    settings.SMS_VENDORS = {}

    with pytest.raises(ImproperlyConfigured, match="No SMS_VENDORS entry for vendor 'twilio'"):
        get_vendor("twilio")


def test_vendor_with_bad_settings_entry(settings):
    settings.SMS_VENDORS = {"twilio": {"account_sid": "sid"}}

    with pytest.raises(ImproperlyConfigured, match="Could not build SMS vendor 'twilio'"):
        get_vendor("twilio")
