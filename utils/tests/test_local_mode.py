"""LOCAL_MODE: the registration flow runs with no external service configured.

Nothing here mocks Connect, Google or Twilio. If a test below ever needs a mock, LOCAL_MODE has
regressed.
"""

import os
import subprocess
import sys
from unittest import mock

import pytest
from django.conf import settings as django_settings
from django.urls import reverse
from phonenumbers.phonenumberutil import NumberParseException

from utils.app_integrity.const import ErrorCodes as AppIntegrityErrorCodes
from utils.connect import (
    check_number_for_existing_invites,
    get_connect_toggles,
    resend_connect_invite,
    update_connect_user_profile,
)


@pytest.fixture
def local_mode(settings):
    settings.LOCAL_MODE = True


@pytest.fixture
def no_outbound_http():
    """Fail the test if anything tries to leave the process over HTTP."""
    with (
        mock.patch("utils.connect.requests.get", side_effect=AssertionError("outbound HTTP in LOCAL_MODE")),
        mock.patch("utils.connect.requests.post", side_effect=AssertionError("outbound HTTP in LOCAL_MODE")),
    ):
        yield


def test_local_mode_refuses_to_start_without_debug():
    env = {**os.environ, "LOCAL_MODE": "True", "DEBUG": "False"}
    result = subprocess.run(
        [sys.executable, "-c", "import connectid.settings"],
        cwd=django_settings.BASE_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "LOCAL_MODE requires DEBUG=True" in result.stderr


@pytest.mark.usefixtures("local_mode", "no_outbound_http")
class TestConnectCallsAreSkipped:
    def test_no_number_is_invited(self):
        assert check_number_for_existing_invites("+12025550100") is False

    def test_malformed_numbers_are_still_rejected(self):
        with pytest.raises(NumberParseException):
            check_number_for_existing_invites("not-a-phone-number")

    def test_toggles_come_from_this_server_only(self):
        assert get_connect_toggles(phone_number="+12025550100") == {}

    def test_profile_and_invite_pushes_are_dropped(self, user):
        resend_connect_invite(user)
        update_connect_user_profile(user.username, "New Name")


@pytest.mark.django_db
@pytest.mark.usefixtures("local_mode", "no_outbound_http")
class TestRegistrationWithoutExternalServices:
    def test_start_configuration_needs_no_integrity_headers(self, client):
        response = client.post(reverse("start_device_configuration"), data={"phone_number": "+74261234567"})

        assert response.status_code == 200
        assert response.json()["demo_user"] is True
        assert response.json()["toggles"] == {}

    def test_start_configuration_still_rejects_a_malformed_number(self, client):
        response = client.post(reverse("start_device_configuration"), data={"phone_number": "not a number"})

        assert response.status_code == 503
        assert response.json()["error_code"] == AppIntegrityErrorCodes.MALFORMED_PHONE_NUMBER

    def test_report_integrity_answers_without_google(self, client):
        response = client.post(
            reverse("report_integrity"),
            data={"request_id": "r1", "cc_device_id": "d1"},
            HTTP_CC_INTEGRITY_TOKEN="token",
            HTTP_CC_REQUEST_HASH="hash",
        )

        assert response.status_code == 200
        assert response.json() == {"result_code": None}
