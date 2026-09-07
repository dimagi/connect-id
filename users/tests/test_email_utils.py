from smtplib import SMTPException
from unittest.mock import patch

import pytest

from users.email_utils import mask_email, send_email_otp_message


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

    @pytest.mark.parametrize(
        "bad_email",
        [
            "notanemail",
            "@nodomain.com",
            "missingdomain@",
            "double@@example.com",
            "spaces in@email.com",
        ],
    )
    @patch("users.email_utils.send_mail")
    def test_invalid_email_skips_send(self, mock_send_mail, bad_email):
        send_email_otp_message(bad_email, "123456", 30)
        mock_send_mail.assert_not_called()


class TestMaskEmail:
    @pytest.mark.parametrize(
        "email, expected",
        [
            # Three characters or fewer are masked outright.
            ("a@dimagi.com", "*@dimagi.com"),
            ("ab@dimagi.com", "**@dimagi.com"),
            ("abc@dimagi.com", "***@dimagi.com"),
            # Longer local parts keep their first and last character.
            ("abcd@dimagi.com", "a**d@dimagi.com"),
            ("abcde@dimagi.com", "a***e@dimagi.com"),
            ("abcdef@dimagi.com", "a****f@dimagi.com"),
            ("abcdefg@dimagi.com", "a*****g@dimagi.com"),
            (
                "ihaveaverylongemailname@dimagi.com",
                "i*********************e@dimagi.com",
            ),
        ],
    )
    def test_masks_local_part(self, email, expected):
        assert mask_email(email) == expected

    @pytest.mark.parametrize("email", ["notanemail", "@dimagi.com", ""])
    def test_unrecognised_shapes_are_masked_entirely(self, email):
        masked = mask_email(email)
        assert set(masked) <= {"*"}
        assert len(masked) == len(email)
