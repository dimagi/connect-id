import secrets

from django.db import transaction

from users.exceptions import UnlockUserError
from users.models import ConnectUser


def find_inactive_users(phone_number):
    """Locked-out accounts on a phone number, newest first."""
    return ConnectUser.objects.filter(phone_number=phone_number, is_active=False, is_locked=True).order_by(
        "-date_joined"
    )


def get_active_user(phone_number):
    """The one active account on a phone number, or None."""
    return ConnectUser.objects.filter(phone_number=phone_number, is_active=True).first()


def find_unlock_candidates(phone_number=None, user_id=None):
    """Inactive accounts the unlock page may act on, looked up by phone number or by id.

    Unlike get_inactive_user this reports ambiguity to the caller instead of failing on it,
    so the admin can show the choice.
    """
    if user_id:
        return list(ConnectUser.objects.filter(id=user_id, is_active=False))
    return list(find_inactive_users(phone_number))


def get_inactive_user(phone_number, inactive_user_id=None):
    if inactive_user_id:
        return ConnectUser.objects.get(id=inactive_user_id)

    try:
        inactive_user = ConnectUser.objects.get(phone_number=phone_number, is_active=False, is_locked=True)
    except (ConnectUser.MultipleObjectsReturned, ConnectUser.DoesNotExist):
        raise UnlockUserError(
            "Failed to query for inactive user. Please use a user ID instead, "
            "or ensure that there aren't multiple inactive users."
        )
    return inactive_user


@transaction.atomic
def unlock_user(inactive_user, disable_current_active_user=True):
    if disable_current_active_user:
        ConnectUser.objects.filter(phone_number=inactive_user.phone_number, is_active=True).update(is_active=False)

    inactive_user.is_locked = False
    inactive_user.is_active = True
    inactive_user.reset_failed_backup_code_attempts()
    inactive_user.save()


def generate_backup_code(user):
    # Generates a random 6-digit backup code
    backup_code = str(secrets.randbelow(900000) + 100000)
    user.set_recovery_pin(backup_code)
    user.save()
    return backup_code
