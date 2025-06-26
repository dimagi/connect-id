import secrets

from django.core.management.base import BaseCommand, CommandError

from users.models import ConnectUser


class Command(BaseCommand):
    help = "Unlock a user and generate a new backup code for them"

    def add_arguments(self, parser):
        parser.add_argument("--phone_number", type=str, required=False)
        parser.add_argument("--inactive_user_id", type=str, required=False, help="User ID of inactive user to unlock")
        parser.add_argument("--disable_current_active_user", action="store_true")

    def handle(self, *args, **options):
        phone_number = options.get("phone_number")
        inactive_user_id = options.get("inactive_user_id")
        if bool(phone_number) == bool(inactive_user_id):
            raise CommandError("Please only provide either a phone number or an inactive user ID")

        disable_current_active_user = options.get("disable_current_active_user", True)

        inactive_user = get_inactive_user(phone_number, inactive_user_id)
        unlock_user(inactive_user, disable_current_active_user)
        backup_code = generate_backup_code(inactive_user)
        print(f"User {phone_number} has been unlocked and a backup code has been generated: {backup_code}")


def get_inactive_user(phone_number, inactive_user_id=None):
    if inactive_user_id:
        return ConnectUser.objects.get(id=inactive_user_id)

    try:
        inactive_user = ConnectUser.objects.get(phone_number=phone_number, is_active=False, is_locked=True)
    except (ConnectUser.MultipleObjectsReturned, ConnectUser.DoesNotExist):
        raise CommandError(
            "Failed to query for inactive user. Please use a user ID instead, "
            "or ensure that there aren't multiple inactive users."
        )
    return inactive_user


def unlock_user(inactive_user, disable_current_active_user=True):
    if disable_current_active_user:
        ConnectUser.objects.filter(phone_number=inactive_user.phone_number, is_active=True).update(is_active=False)

    inactive_user.is_locked = False
    inactive_user.is_active = True
    inactive_user.save()


def generate_backup_code(user):
    # Generates a random 6-digit backup code
    backup_code = str(secrets.randbelow(900000) + 100000)
    user.set_recovery_pin(backup_code)
    user.save()
    return backup_code
