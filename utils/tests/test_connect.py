from unittest import mock

import pytest
import requests
from django.conf import settings

from utils.connect import (
    CONNECT_REQUEST_TIMEOUT,
    check_number_for_existing_invites,
    get_connect_toggles,
    update_connect_user_profile,
)


class TestCheckNumberForExistingInvites:
    @mock.patch("utils.connect.requests.get")
    def test_returns_invited_value(self, mock_get):
        mock_get.return_value.json.return_value = {"invited": True}
        assert check_number_for_existing_invites("+12025550100") is True

    @mock.patch("utils.connect.requests.get")
    def test_propagates_request_exceptions(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("upstream slow")
        with pytest.raises(requests.exceptions.Timeout):
            check_number_for_existing_invites("+12025550100")


class TestGetConnectToggles:
    @mock.patch("utils.connect.requests.get")
    def test_returns_parsed_toggles_on_success(self, mock_get):
        mock_get.return_value.json.return_value = {
            "toggles": [
                {"name": "feature_a", "active": True, "created": "2025-01-01", "modified": "2025-01-02"},
            ]
        }
        result = get_connect_toggles(username="alice")
        assert result == {
            "feature_a": {"active": True, "created_at": "2025-01-01", "modified_at": "2025-01-02"},
        }

    @pytest.mark.parametrize(
        "exc",
        [
            requests.exceptions.Timeout("upstream timed out"),
            requests.exceptions.ConnectionError("upstream unreachable"),
        ],
    )
    @mock.patch("utils.connect.requests.get")
    def test_raises_when_upstream_fails(self, mock_get, exc):
        mock_get.side_effect = exc
        with pytest.raises(requests.exceptions.RequestException):
            get_connect_toggles(username="alice")


class TestUpdateConnectUserProfile:
    @mock.patch("utils.connect.requests.post")
    def test_posts_username_and_name(self, mock_post):
        update_connect_user_profile("abc123", "New Name")

        args, kwargs = mock_post.call_args
        assert args[0] == settings.CONNECT_UPDATE_PROFILE_URL
        assert kwargs["data"] == {"username": "abc123", "name": "New Name"}
        assert kwargs["auth"] == (
            settings.COMMCARE_CONNECT_CLIENT_ID,
            settings.COMMCARE_CONNECT_CLIENT_SECRET,
        )
        assert kwargs["timeout"] == CONNECT_REQUEST_TIMEOUT

    @mock.patch("utils.connect.requests.post")
    def test_raises_on_error_response(self, mock_post):
        mock_post.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError("500")

        with pytest.raises(requests.exceptions.HTTPError):
            update_connect_user_profile("abc123", "New Name")
