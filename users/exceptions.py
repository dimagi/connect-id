class RecoveryPinNotSetError(Exception):
    pass


class RateLimitedError(Exception):
    def __init__(self, retry_after_seconds):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Rate limited. Retry after {retry_after_seconds} seconds.")


class AccountLockedError(Exception):
    pass


class IncorrectBackupCodeError(Exception):
    def __init__(self, attempts_left):
        self.attempts_left = attempts_left
        super().__init__(f"Incorrect backup code. {attempts_left} attempts left.")


class IncorrectOTPError(Exception):
    def __init__(self, attempts_left):
        self.attempts_left = attempts_left
        super().__init__(f"Incorrect OTP. {attempts_left} attempts left.")


class OTPLimitExceededError(Exception):
    def __init__(self, retry_after_seconds):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"OTP attempts exhausted. Retry after {retry_after_seconds} seconds.")
