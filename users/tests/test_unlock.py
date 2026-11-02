import pytest

from users.exceptions import UnlockUserError
from users.factories import UserFactory
from users.models import ConnectUser
from users.unlock import (
    find_unlock_candidates,
    get_active_user,
    get_user_to_unlock,
    unlock_and_issue_backup_code,
)

PHONE = "+27821234567"


@pytest.mark.django_db
class TestGetActiveUser:
    def test_returns_the_active_user(self):
        active = UserFactory.create(phone_number=PHONE)
        UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        assert get_active_user(PHONE).pk == active.pk

    def test_returns_none_when_no_active_user(self):
        UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        assert get_active_user(PHONE) is None


@pytest.mark.django_db
class TestFindUnlockCandidates:
    def test_by_phone_number(self):
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        assert [u.pk for u in find_unlock_candidates(phone_number=PHONE)] == [locked.pk]

    def test_by_phone_number_returns_newest_first(self):
        older, newer = UserFactory.create_batch(2, phone_number=PHONE, is_active=False, is_locked=True)
        ConnectUser.objects.filter(pk=newer.pk).update(date_joined="2030-01-01T00:00:00Z")

        assert [u.pk for u in find_unlock_candidates(phone_number=PHONE)] == [newer.pk, older.pk]

    def test_by_phone_number_excludes_active_and_unlocked_users(self):
        UserFactory.create(phone_number=PHONE)
        UserFactory.create(phone_number=PHONE, is_active=False, is_locked=False)

        assert find_unlock_candidates(phone_number=PHONE) == []

    def test_by_phone_number_includes_active_locked_users(self):
        active_locked = UserFactory.create(phone_number=PHONE, is_locked=True)

        assert [u.pk for u in find_unlock_candidates(phone_number=PHONE)] == [active_locked.pk]

    def test_by_user_id_does_not_require_is_locked(self):
        inactive = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=False)

        assert [u.pk for u in find_unlock_candidates(user_id=inactive.pk)] == [inactive.pk]

    def test_by_user_id_excludes_active_unlocked_users(self):
        active = UserFactory.create(phone_number=PHONE)

        assert find_unlock_candidates(user_id=active.pk) == []

    def test_by_user_id_includes_active_locked_users(self):
        active_locked = UserFactory.create(phone_number=PHONE, is_locked=True)

        assert [u.pk for u in find_unlock_candidates(user_id=active_locked.pk)] == [active_locked.pk]


@pytest.mark.django_db
class TestGetUserToUnlock:
    def test_by_phone_number(self, locked_user):
        assert get_user_to_unlock(locked_user.phone_number).pk == locked_user.pk

    def test_by_user_id(self, locked_user):
        assert get_user_to_unlock(phone_number=None, user_id=locked_user.pk).pk == locked_user.pk

    def test_multiple_matches_is_an_unlock_error(self):
        UserFactory.create_batch(2, phone_number=PHONE, is_active=False, is_locked=True)

        with pytest.raises(UnlockUserError):
            get_user_to_unlock(PHONE)

    def test_by_phone_number_finds_an_active_locked_user(self):
        active_locked = UserFactory.create(phone_number=PHONE, is_locked=True)

        assert get_user_to_unlock(PHONE).pk == active_locked.pk

    def test_active_and_inactive_locked_users_are_ambiguous(self):
        # An inactive locked account predates locks leaving the account active.
        UserFactory.create(phone_number=PHONE, is_locked=True)
        UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        with pytest.raises(UnlockUserError, match="use a user ID"):
            get_user_to_unlock(PHONE)

    def test_no_match_is_an_unlock_error(self):
        with pytest.raises(UnlockUserError):
            get_user_to_unlock(PHONE)

    def test_inactive_but_not_locked_is_an_unlock_error(self):
        UserFactory.create(phone_number=PHONE, is_active=False, is_locked=False)

        with pytest.raises(UnlockUserError):
            get_user_to_unlock(PHONE)

    def test_unknown_user_id_is_an_unlock_error(self):
        with pytest.raises(UnlockUserError):
            get_user_to_unlock(phone_number=None, user_id=-1)

    def test_active_user_id_is_still_accepted(self):
        # Naming an id is an operator override, so the id path stays unfiltered.
        active = UserFactory.create(phone_number=PHONE)

        assert get_user_to_unlock(phone_number=None, user_id=active.pk).pk == active.pk


@pytest.mark.django_db
class TestUnlockAndIssueBackupCode:
    def test_returns_a_six_digit_code_that_the_account_accepts(self, locked_user):
        backup_code = unlock_and_issue_backup_code(locked_user)

        locked_user.refresh_from_db()
        assert len(backup_code) == 6
        assert isinstance(backup_code, str)
        assert locked_user.check_recovery_pin(backup_code) is True

    def test_activates_the_account_and_clears_the_lock(self, locked_user):
        unlock_and_issue_backup_code(locked_user)

        locked_user.refresh_from_db()
        assert locked_user.is_locked is False
        assert locked_user.is_active is True
        assert locked_user.failed_backup_code_attempts == 0

    def test_deactivates_the_current_active_account(self, locked_user):
        active = UserFactory.create(phone_number=locked_user.phone_number)

        unlock_and_issue_backup_code(locked_user, disable_current_active_user=True)

        active.refresh_from_db()
        assert active.is_active is False

    def test_unlocking_the_active_account_keeps_it_active(self):
        active_locked = UserFactory.create(phone_number=PHONE, is_locked=True, failed_backup_code_attempts=3)

        unlock_and_issue_backup_code(active_locked, disable_current_active_user=True)

        active_locked.refresh_from_db()
        assert active_locked.is_active is True
        assert active_locked.is_locked is False
        assert active_locked.failed_backup_code_attempts == 0

    def test_active_user_stays_active_when_the_unlock_fails(self, monkeypatch):
        active = UserFactory.create(phone_number=PHONE)
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        def boom(*args, **kwargs):
            raise RuntimeError("save failed")

        monkeypatch.setattr(ConnectUser, "save", boom)

        with pytest.raises(RuntimeError):
            unlock_and_issue_backup_code(locked)

        active.refresh_from_db()
        assert active.is_active is True
