import json
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from utils.app_integrity.exceptions import DeviceIntegrityError, IntegrityRequestError  # AccountDetailsError,
from utils.app_integrity.google_play_integrity import AppIntegrityService
from utils.app_integrity.schemas import VerdictResponse


def get_verdict(response_filepath):
    with open(response_filepath) as file_data:
        verdict_response = json.load(file_data)

    return verdict_response


@contextmanager
def does_not_raise():
    yield


class TestAppIntegrityService:
    request_hash = "aGVsbG8gd29scmQgdGhlcmU"

    @pytest.mark.parametrize(
        "verdict, exception, error_message",
        [
            (
                get_verdict(response_filepath="utils/tests/data/request_hash_mismatch_response.json"),
                pytest.raises(IntegrityRequestError),
                "Request hash mismatch",
            ),
            (
                get_verdict(response_filepath="utils/tests/data/package_mismatch_response.json"),
                pytest.raises(IntegrityRequestError),
                "Request package name mismatch",
            ),
            (
                get_verdict(response_filepath="utils/tests/data/device_integrity_unmet_response.json"),
                pytest.raises(DeviceIntegrityError),
                "Device integrity compromised",
            ),
            # (
            #     get_verdict(response_filepath="utils/tests/data/unlicensed_response.json"),
            #     pytest.raises(AccountDetailsError),
            #     "Account not licensed",
            # ),
            (
                get_verdict(response_filepath="utils/tests/data/success_integrity_response.json"),
                does_not_raise(),
                "",
            ),
        ],
    )
    @patch.object(AppIntegrityService, "_obtain_verdict")
    def test_verdict_analysis(self, obtain_verdict_mock, verdict, exception, error_message):
        obtain_verdict_mock.return_value = VerdictResponse.from_dict(verdict["tokenPayloadExternal"])
        service = AppIntegrityService(token="test_token", request_hash=self.request_hash)

        with exception as exc_info:
            service.verify_integrity()

        if error_message:
            assert str(exc_info.value) == error_message
        else:
            assert exc_info is None

    @pytest.mark.parametrize(
        "verdict, is_demo_user, exception, error_message",
        [
            (
                get_verdict(response_filepath="utils/tests/data/emulated_device_meets_integrity_response.json"),
                True,
                does_not_raise(),
                "",
            ),
            (
                get_verdict(response_filepath="utils/tests/data/emulated_device_unmet_response.json"),
                True,
                does_not_raise(),
                "",
            ),
            (
                get_verdict(response_filepath="utils/tests/data/emulated_device_meets_integrity_response.json"),
                False,
                does_not_raise(),
                "",
            ),
            (
                get_verdict(response_filepath="utils/tests/data/emulated_device_unmet_response.json"),
                False,
                pytest.raises(DeviceIntegrityError),
                "Device integrity compromised",
            ),
        ],
    )
    @patch.object(AppIntegrityService, "_obtain_verdict")
    def test_verdict_analysis_for_demo_user(
        self, obtain_verdict_mock, verdict, is_demo_user, exception, error_message
    ):
        obtain_verdict_mock.return_value = VerdictResponse.from_dict(verdict["tokenPayloadExternal"])
        service = AppIntegrityService(token="test_token", request_hash=self.request_hash, is_demo_user=is_demo_user)

        with exception as exc_info:
            service.verify_integrity()

        if error_message:
            assert str(exc_info.value) == error_message
        else:
            assert exc_info is None
