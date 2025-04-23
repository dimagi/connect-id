from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import factory
import pytest

from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.google_play_integrity import AppIntegrityService
from utils.app_integrity.schemas import VerdictResponse
from utils.twilio import lookup_telecom_provider


class TestLookupTelecomProvider:
    @patch("utils.twilio.Client")
    def test_lookup_telecom_provider_success(self, mock_client):
        mock_phone_info = MagicMock()
        mock_phone_info.carrier = {"name": "Test Carrier"}
        mock_client.return_value.lookups.v1.phone_numbers.return_value.fetch.return_value = mock_phone_info

        phone_number = factory.Faker("phone_number")
        result = lookup_telecom_provider(phone_number)

        assert result == "Test Carrier"
        mock_client.return_value.lookups.v1.phone_numbers.assert_called_once_with(phone_number)
        mock_client.return_value.lookups.v1.phone_numbers.return_value.fetch.assert_called_once_with(type="carrier")

    @patch("utils.twilio.Client")
    def test_lookup_telecom_provider_failure(self, mock_client):
        mock_client.return_value.lookups.v1.phone_numbers.return_value.fetch.side_effect = Exception("Test error")

        phone_number = factory.Faker("phone_number")
        result = lookup_telecom_provider(phone_number)

        assert result is None
        mock_client.return_value.lookups.v1.phone_numbers.assert_called_once_with(phone_number)
        mock_client.return_value.lookups.v1.phone_numbers.return_value.fetch.assert_called_once_with(type="carrier")


def get_verdict(**kwargs):
    return {
        "requestDetails": {
            "requestPackageName": kwargs.get("requestPackageName", "org.commcare.dalvik"),
            "requestHash": kwargs.get("requestHash", "test_hash"),
            "timestampMillis": kwargs.get("timestampMillis", "1234567890"),
        },
        "appIntegrity": {
            "appRecognitionVerdict": kwargs.get("appRecognitionVerdict", "PLAY_RECOGNIZED"),
        },
        "deviceIntegrity": {
            "deviceRecognitionVerdict": kwargs.get("deviceRecognitionVerdict", "MEETS_DEVICE_INTEGRITY"),
        },
        "accountDetails": {
            "appLicensingVerdict": kwargs.get("appLicensingVerdict", "LICENSED"),
        },
    }


@contextmanager
def does_not_raise():
    yield


class TestAppIntegrityService:
    request_hash = "test_hash"

    @pytest.mark.parametrize(
        "verdict, exception, error_message",
        [
            (
                get_verdict(requestHash="wrong_hash"),
                pytest.raises(IntegrityRequestError),
                "Request hash mismatch",
            ),
            (
                get_verdict(requestPackageName="what.package.is.this"),
                pytest.raises(IntegrityRequestError),
                "Request package name mismatch",
            ),
            (
                get_verdict(appRecognitionVerdict="NOT_RECOGNIZED"),
                pytest.raises(AppIntegrityError),
                "App not recognized",
            ),
            (
                get_verdict(deviceRecognitionVerdict=""),
                pytest.raises(DeviceIntegrityError),
                "Device integrity compromised",
            ),
            (
                get_verdict(appLicensingVerdict="UNLICENSED"),
                pytest.raises(AccountDetailsError),
                "Account not licensed",
            ),
            (
                get_verdict(),
                does_not_raise(),
                "",
            ),
        ],
    )
    @patch.object(AppIntegrityService, "_obtain_verdict")
    def test_verdict_analysis(self, obtain_verdict_mock, verdict, exception, error_message):
        obtain_verdict_mock.return_value = VerdictResponse.from_dict(verdict)
        service = AppIntegrityService(token="test_token", request_hash=self.request_hash)

        with exception as exc_info:
            service.verify_integrity()

        if error_message:
            assert str(exc_info.value) == error_message
        else:
            assert exc_info is None
