from datetime import timedelta

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils.timezone import now
from faker import Faker

from users.factories import UserFactory


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


@pytest.mark.django_db
class TestReactivateLockedAccountsCommand:
    def test_lone_locked_account_is_reactivated_and_stays_locked(self, capsys):
        user = UserFactory(is_active=False, is_locked=True)

        call_command("reactivate_locked_accounts")

        user.refresh_from_db()
        assert user.is_active is True
        assert user.is_locked is True
        assert "Reactivated 1 account(s)" in capsys.readouterr().out

    def test_only_newest_locked_account_on_a_phone_is_reactivated(self):
        phone_number = Faker().phone_number()
        older = UserFactory(
            phone_number=phone_number, is_active=False, is_locked=True, date_joined=now() - timedelta(days=2)
        )
        newest = UserFactory(phone_number=phone_number, is_active=False, is_locked=True, date_joined=now())

        call_command("reactivate_locked_accounts")

        older.refresh_from_db()
        newest.refresh_from_db()
        assert newest.is_active is True
        assert older.is_active is False

    def test_phone_conflict_with_active_account_is_skipped_and_listed(self, capsys):
        phone_number = Faker().phone_number()
        UserFactory(phone_number=phone_number, is_active=True)
        locked = UserFactory(phone_number=phone_number, is_active=False, is_locked=True)

        call_command("reactivate_locked_accounts")

        locked.refresh_from_db()
        assert locked.is_active is False
        out = capsys.readouterr().out
        assert f"id={locked.pk} " in out
        assert "phone number is in use by an active account" in out

    def test_email_conflict_with_active_account_is_skipped_and_listed(self, capsys):
        UserFactory(email="shared@example.com", is_active=True)
        locked = UserFactory(email="shared@example.com", is_active=False, is_locked=True)

        call_command("reactivate_locked_accounts")

        locked.refresh_from_db()
        assert locked.is_active is False
        out = capsys.readouterr().out
        assert f"id={locked.pk} " in out
        assert "email is in use by an active account" in out

    def test_email_conflict_between_candidates_reactivates_only_the_newest(self, capsys):
        older = UserFactory(
            email="shared@example.com", is_active=False, is_locked=True, date_joined=now() - timedelta(days=2)
        )
        newest = UserFactory(email="shared@example.com", is_active=False, is_locked=True, date_joined=now())

        call_command("reactivate_locked_accounts")

        older.refresh_from_db()
        newest.refresh_from_db()
        assert newest.is_active is True
        assert older.is_active is False
        out = capsys.readouterr().out
        assert f"id={older.pk} " in out
        assert "email is in use by a newer account being reactivated" in out

    def test_dry_run_changes_nothing(self, capsys):
        user = UserFactory(is_active=False, is_locked=True)

        call_command("reactivate_locked_accounts", dry_run=True)

        user.refresh_from_db()
        assert user.is_active is False
        assert "Would reactivate 1 account(s)" in capsys.readouterr().out

    def test_inactive_unlocked_account_is_left_alone(self):
        user = UserFactory(is_active=False, is_locked=False)

        call_command("reactivate_locked_accounts")

        user.refresh_from_db()
        assert user.is_active is False
