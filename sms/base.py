from abc import ABC, abstractmethod
from dataclasses import dataclass

from phonenumber_field.phonenumber import PhoneNumber


@dataclass(frozen=True)
class SmsMessage:
    to: PhoneNumber
    body: str


@dataclass(frozen=True)
class SendResult:
    vendor: str | None
    vendor_message_id: str | None
    skipped: bool = False  # true for test numbers


class SmsSendError(Exception):
    def __init__(self, vendor: str, message: str, vendor_error_code: str | None = None):
        code = f" [{vendor_error_code}]" if vendor_error_code is not None else ""
        super().__init__(f"{vendor}{code}: {message}")
        self.vendor = vendor
        self.vendor_error_code = vendor_error_code


class BaseSmsVendor(ABC):
    name: str

    def send(self, message: SmsMessage) -> SendResult:
        try:
            return self._send(message, self.get_sender(message))
        except SmsSendError:
            raise
        except Exception as e:
            raise SmsSendError(self.name, str(e), self.error_code(e)) from e

    def get_sender(self, message: SmsMessage) -> str | None:
        """Sender ID to send from. None means the vendor picks its own."""
        return None

    def error_code(self, exc: Exception) -> str | None:
        """The vendor's own code for a failure. None if it does not have one."""
        return None

    @abstractmethod
    def _send(self, message: SmsMessage, sender: str | None) -> SendResult:
        """Call the vendor's API. Raise anything; send() converts it."""
