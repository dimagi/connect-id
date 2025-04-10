from unittest.mock import MagicMock, patch

from utils.twilio import lookup_telecom_provider


class TestLookupTelecomProvider:
    @patch("utils.twilio.Client")
    def test_lookup_telecom_provider_success(self, mock_client):
        mock_phone_info = MagicMock()
        mock_phone_info.carrier = {"name": "Test Carrier"}
        mock_client.return_value.lookups.v1.phone_numbers.return_value.fetch.return_value = mock_phone_info

        phone_number = "+1234567890"
        result = lookup_telecom_provider(phone_number)

        assert result == "Test Carrier"
        mock_client.return_value.lookups.v1.phone_numbers.assert_called_once_with(phone_number)
        mock_client.return_value.lookups.v1.phone_numbers.return_value.fetch.assert_called_once_with(type="carrier")

    @patch("utils.twilio.Client")
    def test_lookup_telecom_provider_failure(self, mock_client):
        mock_client.return_value.lookups.v1.phone_numbers.return_value.fetch.side_effect = Exception("Test error")

        phone_number = "+1234567890"
        result = lookup_telecom_provider(phone_number)

        assert result is None
        mock_client.return_value.lookups.v1.phone_numbers.assert_called_once_with(phone_number)
        mock_client.return_value.lookups.v1.phone_numbers.return_value.fetch.assert_called_once_with(type="carrier")
