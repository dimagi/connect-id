import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from faker import Faker

from users.factories import UserFactory

PHONE = "+27821234567"


@pytest.mark.django_db
class TestUnlockAndGenerateBackupCodeCommand:
    def test_ambiguous_phone_number_raises_command_error(self):
        phone_number = Faker().phone_number()
        UserFactory.create_batch(2, phone_number=phone_number, is_active=False, is_locked=True)

        with pytest.raises(CommandError):
            call_command("unlock_and_generate_backup_code", phone_number=phone_number)

    def test_unknown_user_id_raises_command_error(self):
        with pytest.raises(CommandError):
            call_command("unlock_and_generate_backup_code", inactive_user_id=-1)

    def test_successful_unlock_via_the_command(self, locked_user, capsys):
        call_command(
            "unlock_and_generate_backup_code",
            phone_number=str(locked_user.phone_number),
            disable_current_active_user=True,
        )

        locked_user.refresh_from_db()
        assert locked_user.is_locked is False
        assert locked_user.is_active is True

        captured = capsys.readouterr()
        assert "has been unlocked and a backup code has been generated" in captured.out

    def test_unlocks_an_active_locked_user_by_phone_number(self, capsys):
        locked = UserFactory.create(phone_number=PHONE, is_locked=True)

        call_command("unlock_and_generate_backup_code", phone_number=PHONE, disable_current_active_user=True)

        locked.refresh_from_db()
        assert (locked.is_active, locked.is_locked) == (True, False)
        assert "has been unlocked and a backup code has been generated" in capsys.readouterr().out

    def test_unlocks_an_active_locked_user_by_id(self):
        locked = UserFactory.create(phone_number=PHONE, is_locked=True)

        call_command("unlock_and_generate_backup_code", inactive_user_id=str(locked.pk))

        locked.refresh_from_db()
        assert (locked.is_active, locked.is_locked) == (True, False)

    def test_unlocks_an_inactive_locked_user_by_id_and_deactivates_the_active_one(self):
        active = UserFactory.create(phone_number=PHONE)
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        call_command(
            "unlock_and_generate_backup_code", inactive_user_id=str(locked.pk), disable_current_active_user=True
        )

        locked.refresh_from_db()
        active.refresh_from_db()
        assert (locked.is_active, locked.is_locked) == (True, False)
        assert active.is_active is False

    def test_both_kinds_on_one_phone_number_raises_command_error(self):
        UserFactory.create(phone_number=PHONE, is_locked=True)
        UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        with pytest.raises(CommandError):
            call_command("unlock_and_generate_backup_code", phone_number=PHONE)
