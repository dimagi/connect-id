import secrets

from django.db import transaction
from django.db.models import Q

from users.exceptions import UnlockUserError
from users.models import ConnectUser


def find_unlock_candidates(phone_number=None, user_id=None):
    """Accounts the unlock flow may act on, looked up by phone number or by id.

    Locked accounts match whether active (locked since CCCT-2918) or inactive (the legacy
    scheme). The phone-number path returns them newest first, and reports ambiguity to the
    caller instead of failing on it so the admin can offer the choice. The id path also
    admits an inactive account that is not locked.
    """
    if user_id:
        return list(ConnectUser.objects.filter(Q(is_active=False) | Q(is_locked=True), id=user_id))
    return list(ConnectUser.objects.filter(phone_number=phone_number, is_locked=True).order_by("-date_joined"))


def get_active_user(phone_number):
    """The one active account on a phone number, or None."""
    return ConnectUser.objects.filter(phone_number=phone_number, is_active=True).first()


def get_inactive_user(phone_number, inactive_user_id=None):
    """The single account the command should unlock, by phone number or by id.

    The id path stays unfiltered on purpose: naming an id is an operator override, so an
    account that is already active or already unlocked is still accepted there.
    """
    if inactive_user_id:
        try:
            return ConnectUser.objects.get(id=inactive_user_id)
        except ConnectUser.DoesNotExist:
            raise UnlockUserError(f"No user found with ID {inactive_user_id}.") from None

    candidates = find_unlock_candidates(phone_number=phone_number)
    if len(candidates) != 1:
        raise UnlockUserError(
            "Failed to query for a locked user. Please use a user ID instead, "
            "or ensure that there aren't multiple locked users."
        )
    return candidates[0]


@transaction.atomic
def unlock_and_issue_backup_code(user, disable_current_active_user=True):
    """Unlock the account and return a fresh 6-digit backup code.

    Both entry points go through here, so the unlock and the code that makes the account
    reachable again can never be committed apart, and the row is written once. An account
    that is already active is the active one on its phone number, so nobody is deactivated.
    """
    deactivate_others = disable_current_active_user and not user.is_active
    # Hash before the UPDATE below takes a row lock, so the lock is not held for the hash.
    backup_code = str(secrets.randbelow(900000) + 100000)
    user.set_recovery_pin(backup_code)
    user.is_locked = False
    user.is_active = True
    user.reset_failed_backup_code_attempts()

    if deactivate_others:
        ConnectUser.objects.filter(phone_number=user.phone_number, is_active=True).update(is_active=False)

    user.save(update_fields=["is_active", "is_locked", "failed_backup_code_attempts", "recovery_pin"])
    return backup_code
