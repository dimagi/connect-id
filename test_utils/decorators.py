import functools
from unittest import mock

from utils.app_integrity.google_play_integrity import AppIntegrityService


def skip_app_integrity_check(test_func):
    @functools.wraps(test_func)
    def wrapper(*args, **kwargs):
        with mock.patch.object(AppIntegrityService, "verify_integrity") as verify_integrity_mock:
            with mock.patch("utils.app_integrity.decorators.check_number_for_existing_invites"):
                verify_integrity_mock.return_value = None
                return test_func(*args, **kwargs)

    return wrapper
