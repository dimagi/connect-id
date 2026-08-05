from unittest import mock

import pytest
import requests

from utils.connect import check_number_for_existing_invites, get_connect_toggles


class TestCheckNumberForExistingInvites:
    @mock.patch("utils.connect.requests.get")
    def test_returns_invited_value(self, mock_get):
        mock_get.return_value.json.return_value = {"invited": True}
        assert check_number_for_existing_invites("+12025550100") is True

    @mock.patch("utils.connect.requests.get")
    def test_sends_phone_number_in_e164_format(self, mock_get):
        mock_get.return_value.json.return_value = {"invited": True}
        check_number_for_existing_invites("+23401051962390")
        assert mock_get.call_args.kwargs["params"] == {"phone_number": "+2341051962390"}

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
