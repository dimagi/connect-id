import pytest
from faker import Faker

from users.factories import UserFactory
from users.management.commands.unlock_and_generate_backup_code import (
    generate_backup_code,
    get_inactive_user,
    unlock_user,
)
from users.models import ConnectUser


@pytest.mark.django_db
class TestUnlockAndGenerateBackupCode:
    def test_get_inactive_user(self, locked_user):
        user = get_inactive_user(locked_user.phone_number)
        assert user.id == locked_user.id

        inactive_user = get_inactive_user(phone_number=None, inactive_user_id=locked_user.id)
        assert inactive_user.id == locked_user.id

    def test_get_inactive_but_not_locked_user(self):
        inactive_user = UserFactory.create(phone_number=Faker().phone_number(), is_active=False)
        user = get_inactive_user(inactive_user.phone_number)
        assert user.id == inactive_user.id

    def test_multiple_inactive_users(self):
        phone_number = Faker().phone_number()
        UserFactory.create_batch(2, phone_number=phone_number, is_active=False, is_locked=True)
        with pytest.raises(ConnectUser.MultipleObjectsReturned):
            get_inactive_user(phone_number)

    def test_no_inactive_user(self):
        phone_number = Faker().phone_number()
        with pytest.raises(ConnectUser.DoesNotExist):
            get_inactive_user(phone_number)
        with pytest.raises(ConnectUser.DoesNotExist):
            get_inactive_user(phone_number=None, inactive_user_id=-1)

    def test_unlock_user(self, locked_user):
        unlocked_user = unlock_user(locked_user)
        assert unlocked_user.is_locked is False
        assert unlocked_user.is_active is True

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
