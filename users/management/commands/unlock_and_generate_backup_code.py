import secrets

from django.core.management.base import BaseCommand

from users.models import ConnectUser


class Command(BaseCommand):
    help = "Unlock a user and generate a new backup code for them"

    def add_arguments(self, parser):
        parser.add_argument("--phone-number", type=str, required=False)
        parser.add_argument("--inactive-user-id", type=str, required=False, help="User ID of inactive user to unlock")
        parser.add_argument("--disable-current-active-user", action="store_true")

    def handle(self, *args, **options):
        phone_number = options.get("phone-number")
        inactive_user_id = options.get("inactive-user-id")
        if not phone_number and not inactive_user_id:
            print("Please provide either a phone number or an inactive user ID")
            return

        disable_current_active_user = options.get("disable-current-active-user", True)

        inactive_user = get_inactive_user(phone_number, inactive_user_id)
        user = unlock_user(inactive_user, disable_current_active_user)
        if user:
            backup_code = generate_backup_code(user)
            print(f"User {phone_number} has been unlocked and a backup code has been generated: {backup_code}")
        else:
            print(f"Failed to unlock user with phone number {phone_number}.")


def get_inactive_user(phone_number, inactive_user_id=None):
    if inactive_user_id:
        return ConnectUser.objects.get(id=inactive_user_id)

    # Old accounts might only be set as inactive without being locked, so default to checking for only inactive
    # if no locked user is found
    try:
        inactive_user = ConnectUser.objects.get(phone_number=phone_number, is_active=False, is_locked=True)
    except (ConnectUser.MultipleObjectsReturned, ConnectUser.DoesNotExist):
        inactive_user = ConnectUser.objects.get(phone_number=phone_number, is_active=False)
    return inactive_user


def unlock_user(inactive_user, disable_current_active_user=True):
    if not inactive_user:
        return

    if disable_current_active_user:
        active_user = ConnectUser.objects.filter(phone_number=inactive_user.phone_number, is_active=True).first()
        if active_user:
            active_user.is_active = False
            active_user.save()

    inactive_user.is_locked = False
    inactive_user.is_active = True
    inactive_user.save()
    return inactive_user


def generate_backup_code(user):
    # Generates a random 6-digit backup code
    backup_code = str(secrets.randbelow(900000) + 100000)
    user.set_recovery_pin(backup_code)
    user.save()
    return backup_code
