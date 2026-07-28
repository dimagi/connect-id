import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from faker import Faker

from users.exceptions import UnlockUserError
from users.factories import UserFactory
from users.models import ConnectUser
from users.unlock import generate_backup_code, get_inactive_user, unlock_user


@pytest.mark.django_db
class TestUnlockAndGenerateBackupCode:
    def test_get_inactive_user(self, locked_user):
        user = get_inactive_user(locked_user.phone_number)
        assert user.id == locked_user.id

        inactive_user = get_inactive_user(phone_number=None, inactive_user_id=locked_user.id)
        assert inactive_user.id == locked_user.id

    def test_get_inactive_but_not_locked_user(self):
        inactive_user = UserFactory.create(phone_number=Faker().phone_number(), is_active=False)
        with pytest.raises(UnlockUserError):
            get_inactive_user(inactive_user.phone_number)

    def test_multiple_inactive_users(self):
        phone_number = Faker().phone_number()
        UserFactory.create_batch(2, phone_number=phone_number, is_active=False, is_locked=True)
        with pytest.raises(UnlockUserError):
            get_inactive_user(phone_number)

    def test_no_inactive_user(self):
        phone_number = Faker().phone_number()
        with pytest.raises(UnlockUserError):
            get_inactive_user(phone_number)
        with pytest.raises(ConnectUser.DoesNotExist):
            get_inactive_user(phone_number=None, inactive_user_id=-1)

    def test_unlock_user(self, locked_user):
        unlock_user(locked_user)
        locked_user.refresh_from_db()
        assert locked_user.is_locked is False
        assert locked_user.is_active is True
        assert locked_user.failed_backup_code_attempts == 0

    def test_disable_active_user(self, locked_user):
        active_user = UserFactory.create(phone_number=locked_user.phone_number)
        unlock_user(locked_user, disable_current_active_user=True)
        inactive_user = ConnectUser.objects.get(id=active_user.id)
        assert inactive_user.is_active is False

    def test_generate_backup_code(self, user):
        backup_code = generate_backup_code(user)
        assert len(backup_code) == 6
        assert isinstance(backup_code, str)

        updated_user = ConnectUser.objects.get(id=user.id)
        assert updated_user.check_recovery_pin(backup_code) is True


@pytest.mark.django_db
class TestUnlockAndGenerateBackupCodeCommand:
    def test_ambiguous_phone_number_raises_command_error(self):
        phone_number = Faker().phone_number()
        UserFactory.create_batch(2, phone_number=phone_number, is_active=False, is_locked=True)

        with pytest.raises(CommandError):
            call_command("unlock_and_generate_backup_code", phone_number=phone_number)

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
