import functools
from unittest import mock

from utils.app_integrity.google_play_integrity import AppIntegrityService


def pass_app_integrity_test(test_func):
    @functools.wraps(test_func)
    def wrapper(*args, **kwargs):
        with mock.patch.object(AppIntegrityService, "verify_integrity") as verify_integrity_mock:
            verify_integrity_mock.return_value = None
            return test_func(*args, **kwargs)

    return wrapper
