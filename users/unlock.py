import secrets

from django.db import transaction

from users.exceptions import UnlockUserError
from users.models import ConnectUser


def find_unlock_candidates(phone_number=None, user_id=None):
    """Inactive accounts the unlock flow may act on, looked up by phone number or by id.

    The phone-number path returns the locked-out accounts newest first, and reports ambiguity
    to the caller instead of failing on it so the admin can offer the choice. The id path also
    admits an inactive account that is not locked.
    """
    if user_id:
        return list(ConnectUser.objects.filter(id=user_id, is_active=False))
    return list(
        ConnectUser.objects.filter(phone_number=phone_number, is_active=False, is_locked=True).order_by("-date_joined")
    )


def get_active_user(phone_number):
    """The one active account on a phone number, or None."""
    return ConnectUser.objects.filter(phone_number=phone_number, is_active=True).first()


def get_inactive_user(phone_number, inactive_user_id=None):
    if inactive_user_id:
        return ConnectUser.objects.get(id=inactive_user_id)

    candidates = find_unlock_candidates(phone_number=phone_number)
    if len(candidates) != 1:
        raise UnlockUserError(
            "Failed to query for inactive user. Please use a user ID instead, "
            "or ensure that there aren't multiple inactive users."
        )
    return candidates[0]


@transaction.atomic
def unlock_and_issue_backup_code(inactive_user, disable_current_active_user=True):
    """Unlock the account and return a fresh 6-digit backup code.

    Both entry points go through here, so the unlock and the code that makes the account
    reachable again can never be committed apart, and the row is written once.
    """
    if disable_current_active_user:
        ConnectUser.objects.filter(phone_number=inactive_user.phone_number, is_active=True).update(is_active=False)

    backup_code = str(secrets.randbelow(900000) + 100000)
    inactive_user.is_locked = False
    inactive_user.is_active = True
    inactive_user.reset_failed_backup_code_attempts()
    inactive_user.set_recovery_pin(backup_code)
    inactive_user.save(update_fields=["is_active", "is_locked", "failed_backup_code_attempts", "recovery_pin"])
    return backup_code
