from django.core.management.base import BaseCommand, CommandError

from users.exceptions import UnlockUserError
from users.unlock import get_user_to_unlock, unlock_and_issue_backup_code


class Command(BaseCommand):
    help = "Unlock a user and generate a new backup code for them"

    def add_arguments(self, parser):
        parser.add_argument("--phone_number", type=str, required=False)
        # Named before locked accounts stayed active; kept so existing invocations still work.
        parser.add_argument("--inactive_user_id", type=str, required=False, help="User ID of the account to unlock")
        parser.add_argument("--disable_current_active_user", action="store_true")

    def handle(self, *args, **options):
        phone_number = options.get("phone_number")
        inactive_user_id = options.get("inactive_user_id")
        if bool(phone_number) == bool(inactive_user_id):
            raise CommandError("Please only provide either a phone number or a user ID")

        disable_current_active_user = options.get("disable_current_active_user", True)

        try:
            user = get_user_to_unlock(phone_number, inactive_user_id)
        except UnlockUserError as e:
            raise CommandError(str(e)) from e
        backup_code = unlock_and_issue_backup_code(user, disable_current_active_user)
        print(f"User {phone_number} has been unlocked and a backup code has been generated: {backup_code}")
