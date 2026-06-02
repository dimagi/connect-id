from smtplib import SMTPException
from unittest.mock import patch

import pytest

from users.email_utils import send_email_otp_message


class TestSendEmailOtpMessage:
    @patch("users.email_utils.send_mail")
    def test_sends_correct_subject_body_and_recipient(self, mock_send_mail):
        send_email_otp_message("user@example.com", "123456", 30)

        mock_send_mail.assert_called_once()
        args = mock_send_mail.call_args[0]
        assert args[0] == "Your PersonalID verification code"
        assert "123456" in args[1]
        assert "30" in args[1]
        assert args[3] == ["user@example.com"]

    @patch("users.email_utils.send_mail")
    def test_delivery_failure_propagates(self, mock_send_mail):
        mock_send_mail.side_effect = SMTPException("connection refused")
        with pytest.raises(SMTPException):
            send_email_otp_message("user@example.com", "654321", 30)
