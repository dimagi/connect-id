import base64
import copy
import hashlib
import json
import time
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from django.urls import reverse
from waffle.testutils import override_switch

from flags.const import INTEGRITY_REQUEST_BINDING
from utils.app_integrity.const import ErrorCodes
from utils.app_integrity.decorators import validate_app_integrity
from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.google_play_integrity import (
    MAX_TOKEN_AGE_SECONDS,
    AppIntegrityService,
    compute_request_hashes,
)


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
            (
                get_verdict(response_filepath="utils/tests/data/unlicensed_response.json"),
                pytest.raises(AccountDetailsError),
                "Account not licensed",
            ),
            (
                get_verdict(response_filepath="utils/tests/data/success_integrity_response.json"),
                does_not_raise(),
                "",
            ),
        ],
    )
    @patch.object(AppIntegrityService, "obtain_verdict")
    def test_verdict_analysis(self, obtain_verdict_mock, verdict, exception, error_message):
        obtain_verdict_mock.return_value = verdict["tokenPayloadExternal"]
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
    @patch.object(AppIntegrityService, "obtain_verdict")
    def test_verdict_analysis_for_demo_user(
        self, obtain_verdict_mock, verdict, is_demo_user, exception, error_message
    ):
        obtain_verdict_mock.return_value = verdict["tokenPayloadExternal"]
        service = AppIntegrityService(token="test_token", request_hash=self.request_hash, is_demo_user=is_demo_user)

        with exception as exc_info:
            service.verify_integrity()

        if error_message:
            assert str(exc_info.value) == error_message
        else:
            assert exc_info is None


class TestValidateAppIntegrity:
    @pytest.mark.parametrize(
        "verdict, error_code, error_sub_code",
        [
            (
                get_verdict(response_filepath="utils/tests/data/request_hash_mismatch_response.json"),
                ErrorCodes.INTEGRITY_ERROR,
                IntegrityRequestError.code,
            ),
            (
                get_verdict(response_filepath="utils/tests/data/package_mismatch_response.json"),
                ErrorCodes.INTEGRITY_ERROR,
                IntegrityRequestError.code,
            ),
            (
                get_verdict(response_filepath="utils/tests/data/device_integrity_unmet_response.json"),
                ErrorCodes.INTEGRITY_ERROR,
                DeviceIntegrityError.code,
            ),
            (
                get_verdict(response_filepath="utils/tests/data/unlicensed_response.json"),
                ErrorCodes.INTEGRITY_ERROR,
                AccountDetailsError.code,
            ),
            (
                get_verdict(response_filepath="utils/tests/data/app_unrecognized_response.json"),
                ErrorCodes.INTEGRITY_ERROR,
                AppIntegrityError.code,
            ),
            (
                get_verdict(response_filepath="utils/tests/data/success_integrity_response.json"),
                None,
                None,
            ),
        ],
    )
    @patch.object(AppIntegrityService, "obtain_verdict")
    def test_validate_app_integrity(self, obtain_verdict_mock, verdict, error_code, error_sub_code):
        obtain_verdict_mock.return_value = verdict["tokenPayloadExternal"]

        response = validate_app_integrity(
            "integrity_token",
            "aGVsbG8gd29scmQgdGhlcmU",
            "org.commcare.dalvik",
            "1234567890",
        )
        if response is None:
            assert error_code is None and error_sub_code is None
        else:
            response_data = json.loads(response.content)

            assert response_data["error_code"] == error_code
            assert response_data["error_sub_code"] == error_sub_code


def sha256_base64(text):
    return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


def verdict_for(request_hash, age_seconds=0):
    """A passing verdict for a token made for `request_hash`, `age_seconds` ago."""
    payload = copy.deepcopy(
        get_verdict(response_filepath="utils/tests/data/success_integrity_response.json")["tokenPayloadExternal"]
    )
    payload["requestDetails"]["requestHash"] = request_hash
    payload["requestDetails"]["timestampMillis"] = str(int((time.time() - age_seconds) * 1000))
    return payload


class TestComputeRequestHashes:
    def test_matches_android_jsonobject(self):
        # What Android's JSONObject(body).toString() writes: compact, keys in order, "/" escaped.
        body = {"phone_number": "+258860005049", "application_id": "org.commcare.dalvik", "device": "SM-A/105é"}
        android_json = '{"phone_number":"+258860005049","application_id":"org.commcare.dalvik","device":"SM-A\\/105é"}'

        assert sha256_base64(android_json) in compute_request_hashes(None, body)

    def test_includes_hash_of_raw_body(self):
        raw_body = b'{"device":"a\\u003db","phone_number":"+258860005049"}'

        hashes = compute_request_hashes(raw_body, {"device": "a=b", "phone_number": "+258860005049"})

        assert base64.b64encode(hashlib.sha256(raw_body).digest()).decode() in hashes


class TestRequestBinding:
    request_hash = "aGVsbG8gd29scmQgdGhlcmU"

    def verify(self, verdict, enforce, expected_hashes=None):
        service = AppIntegrityService(
            token="test_token",
            request_hash=verdict["requestDetails"]["requestHash"],
            expected_request_hashes={self.request_hash} if expected_hashes is None else expected_hashes,
            enforce_request_binding=enforce,
        )
        with patch.object(AppIntegrityService, "obtain_verdict", return_value=verdict):
            service.verify_integrity()

    @pytest.mark.parametrize("enforce", [True, False])
    def test_fresh_token_for_this_request_passes(self, enforce, caplog):
        self.verify(verdict_for(self.request_hash), enforce)

        assert "integrity_request_binding_failed" not in caplog.text

    @pytest.mark.parametrize(
        "token_hash, age_seconds, problems",
        [
            ("b3RoZXIgcmVxdWVzdA==", 0, "hash_mismatch"),
            (request_hash, MAX_TOKEN_AGE_SECONDS + 60, "stale"),
            (request_hash, -(MAX_TOKEN_AGE_SECONDS + 60), "stale"),
        ],
    )
    def test_unbound_token_is_rejected_when_enforced(self, token_hash, age_seconds, problems, caplog):
        with pytest.raises(IntegrityRequestError):
            self.verify(verdict_for(token_hash, age_seconds), enforce=True)

        assert f"problems={problems} enforced=True" in caplog.text

    def test_unbound_token_is_only_logged_when_not_enforced(self, caplog):
        self.verify(verdict_for("b3RoZXIgcmVxdWVzdA==", age_seconds=MAX_TOKEN_AGE_SECONDS + 60), enforce=False)

        assert "problems=hash_mismatch,stale enforced=False" in caplog.text

    def test_skipped_without_expected_hashes(self, caplog):
        service = AppIntegrityService(token="test_token", request_hash="b3RoZXIgcmVxdWVzdA==")
        with patch.object(
            AppIntegrityService, "obtain_verdict", return_value=verdict_for("b3RoZXIgcmVxdWVzdA==", 9999)
        ):
            service.verify_integrity()

        assert "integrity_request_binding_failed" not in caplog.text

    def test_replayed_token_is_rejected_before_google_when_enforced(self, caplog):
        self.verify(verdict_for(self.request_hash), enforce=True)

        with pytest.raises(IntegrityRequestError), patch.object(AppIntegrityService, "obtain_verdict") as obtain:
            AppIntegrityService(
                token="test_token",
                request_hash=self.request_hash,
                expected_request_hashes={self.request_hash},
                enforce_request_binding=True,
            ).verify_integrity()

        obtain.assert_not_called()
        assert "problems=replayed enforced=True" in caplog.text

    def test_replayed_token_is_only_logged_when_not_enforced(self, caplog):
        self.verify(verdict_for(self.request_hash), enforce=False)
        self.verify(verdict_for(self.request_hash), enforce=False)

        assert caplog.text.count("integrity_request_binding_failed") == 1
        assert "problems=replayed enforced=False" in caplog.text

    def test_another_token_is_not_a_replay(self, caplog):
        self.verify(verdict_for(self.request_hash), enforce=True)
        service = AppIntegrityService(
            token="another_token",
            request_hash=self.request_hash,
            expected_request_hashes={self.request_hash},
            enforce_request_binding=True,
        )
        with patch.object(AppIntegrityService, "obtain_verdict", return_value=verdict_for(self.request_hash)):
            service.verify_integrity()

        assert "integrity_request_binding_failed" not in caplog.text

    def test_token_is_not_claimed_without_expected_hashes(self):
        for _ in range(2):
            service = AppIntegrityService(token="test_token", request_hash=self.request_hash)
            with patch.object(AppIntegrityService, "obtain_verdict", return_value=verdict_for(self.request_hash)):
                service.verify_integrity()

        # Sampling (report_integrity) doesn't use up the token for start_configuration.
        self.verify(verdict_for(self.request_hash), enforce=True)

    def test_cache_outage_allows_the_token(self, caplog):
        with patch("utils.app_integrity.google_play_integrity.caches") as caches_mock:
            caches_mock.__getitem__.return_value.add.side_effect = ConnectionError("redis down")
            self.verify(verdict_for(self.request_hash), enforce=True)
            self.verify(verdict_for(self.request_hash), enforce=True)

        assert "Used integrity token cache unavailable" in caplog.text


@pytest.mark.django_db
@patch("users.views.get_user_toggles", new=lambda **kwargs: {})
@patch("utils.app_integrity.decorators.check_number_for_existing_invites", new=lambda phone_number: False)
class TestStartConfigurationRequestBinding:
    @pytest.fixture(autouse=True)
    def enforce_request_binding(self):
        with override_switch(INTEGRITY_REQUEST_BINDING, active=True):
            yield

    body = {
        "phone_number": "+27731234567",
        "application_id": "org.commcare.dalvik",
        "gps_location": "1.0 2.0 0.0 5.0",
        "cc_device_id": "device-1",
    }

    def post(self, api_client, token_hash):
        raw_body = json.dumps(self.body)
        with patch.object(AppIntegrityService, "obtain_verdict", return_value=verdict_for(token_hash)):
            return api_client.post(
                reverse("start_device_configuration"),
                data=raw_body,
                content_type="application/json",
                HTTP_CC_INTEGRITY_TOKEN="token",
                HTTP_CC_REQUEST_HASH=token_hash,
            )

    def test_token_made_for_this_request(self, api_client):
        response = self.post(api_client, sha256_base64(json.dumps(self.body)))

        assert response.status_code == 200

    def test_token_made_for_another_number(self, api_client):
        other_body = {**self.body, "phone_number": "+27731234568"}

        response = self.post(api_client, sha256_base64(json.dumps(other_body)))

        assert response.status_code == 403
        assert response.json() == {
            "error_code": ErrorCodes.INTEGRITY_ERROR,
            "error_sub_code": IntegrityRequestError.code,
        }

    def test_same_token_sent_again(self, api_client):
        token_hash = sha256_base64(json.dumps(self.body))
        assert self.post(api_client, token_hash).status_code == 200

        response = self.post(api_client, token_hash)

        assert response.status_code == 403
        assert response.json()["error_sub_code"] == IntegrityRequestError.code
