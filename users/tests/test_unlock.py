import pytest

from users.exceptions import UnlockUserError
from users.factories import UserFactory
from users.models import ConnectUser
from users.unlock import (
    find_inactive_users,
    find_unlock_candidates,
    get_active_user,
    get_inactive_user,
    unlock_user,
)

PHONE = "+27821234567"


@pytest.mark.django_db
class TestFindInactiveUsers:
    def test_returns_locked_inactive_users_newest_first(self):
        older, newer = UserFactory.create_batch(2, phone_number=PHONE, is_active=False, is_locked=True)
        ConnectUser.objects.filter(pk=newer.pk).update(date_joined="2030-01-01T00:00:00Z")

        found = list(find_inactive_users(PHONE))

        assert [u.pk for u in found] == [newer.pk, older.pk]

    def test_excludes_active_and_unlocked_users(self):
        UserFactory.create(phone_number=PHONE)
        UserFactory.create(phone_number=PHONE, is_active=False, is_locked=False)

        assert list(find_inactive_users(PHONE)) == []


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

    def test_by_user_id_does_not_require_is_locked(self):
        inactive = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=False)

        assert [u.pk for u in find_unlock_candidates(user_id=inactive.pk)] == [inactive.pk]

    def test_by_user_id_excludes_active_users(self):
        active = UserFactory.create(phone_number=PHONE)

        assert find_unlock_candidates(user_id=active.pk) == []


@pytest.mark.django_db
class TestGetInactiveUserRaisesUnlockUserError:
    def test_multiple_matches(self):
        UserFactory.create_batch(2, phone_number=PHONE, is_active=False, is_locked=True)

        with pytest.raises(UnlockUserError):
            get_inactive_user(PHONE)


@pytest.mark.django_db
class TestUnlockUserIsAtomic:
    def test_active_user_stays_active_when_the_unlock_fails(self, monkeypatch):
        active = UserFactory.create(phone_number=PHONE)
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        def boom(*args, **kwargs):
            raise RuntimeError("save failed")

        monkeypatch.setattr(ConnectUser, "save", boom)

        with pytest.raises(RuntimeError):
            unlock_user(locked)

        active.refresh_from_db()
        assert active.is_active is True
