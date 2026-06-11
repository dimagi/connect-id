class RecoveryPinNotSetError(Exception):
    pass


class RateLimitedError(Exception):
    def __init__(self, retry_after_seconds):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Rate limited. Retry after {retry_after_seconds} seconds.")
