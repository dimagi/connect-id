import re

import pytest
from django.contrib.admin.models import CHANGE, LogEntry
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse

from users.factories import UserFactory
from users.models import ConnectUser

PHONE = "+27821234567"
MODEL_BACKEND = "django.contrib.auth.backends.ModelBackend"
BACKUP_CODE_RE = re.compile(r"^\d{6}$")


@pytest.fixture
def unlock_url():
    return reverse("admin:users_connectuser_unlock")


@pytest.fixture
def superuser(db):
    return UserFactory(phone_number="+27821110000", is_staff=True, is_superuser=True)


@pytest.fixture
def su_client(client, superuser):
    client.force_login(superuser, backend=MODEL_BACKEND)
    return client


@pytest.mark.django_db
class TestUnlockPageAccess:
    def test_anonymous_is_redirected_to_login(self, client, unlock_url):
        response = client.get(unlock_url)

        assert response.status_code == 302
        assert "/admin/login/" in response["Location"]

    def test_staff_non_superuser_is_forbidden(self, client, unlock_url):
        staff = UserFactory(phone_number="+27821110001", is_staff=True)
        client.force_login(staff, backend=MODEL_BACKEND)

        assert client.get(unlock_url).status_code == 403

    def test_superuser_gets_the_search_form(self, su_client, unlock_url):
        response = su_client.get(unlock_url)

        assert response.status_code == 200
        assert "search_form" in response.context
        assert response.context.get("confirm_form") is None


@pytest.mark.django_db
class TestUnlockPageSearch:
    def test_single_match_advances_to_confirmation(self, su_client, unlock_url):
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        response = su_client.post(unlock_url, {"phone_number": PHONE, "search": "Search"})

        assert response.status_code == 200
        confirm_form = response.context["confirm_form"]
        assert [choice[0] for choice in confirm_form.fields["unlock_user_id"].choices] == [locked.pk]

    def test_two_matches_are_both_offered(self, su_client, unlock_url):
        first, second = UserFactory.create_batch(2, phone_number=PHONE, is_active=False, is_locked=True)

        response = su_client.post(unlock_url, {"phone_number": PHONE, "search": "Search"})

        assert response.status_code == 200
        offered = {choice[0] for choice in response.context["confirm_form"].fields["unlock_user_id"].choices}
        assert offered == {first.pk, second.pk}

    def test_active_account_is_surfaced(self, su_client, unlock_url):
        active = UserFactory(phone_number=PHONE)
        UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        response = su_client.post(unlock_url, {"phone_number": PHONE, "search": "Search"})

        assert response.context["active_user"].pk == active.pk

    def test_no_match_stays_on_the_search_form(self, su_client, unlock_url):
        response = su_client.post(unlock_url, {"phone_number": PHONE, "search": "Search"})

        assert response.status_code == 200
        assert response.context.get("confirm_form") is None
        assert "No locked account matches that search." in str(response.context["search_form"].non_field_errors())

    def test_search_by_user_id(self, su_client, unlock_url):
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        response = su_client.post(unlock_url, {"user_id": str(locked.pk), "search": "Search"})

        assert [choice[0] for choice in response.context["confirm_form"].fields["unlock_user_id"].choices] == [
            locked.pk
        ]

    def test_both_fields_is_a_form_error(self, su_client, unlock_url):
        response = su_client.post(unlock_url, {"phone_number": PHONE, "user_id": "1", "search": "Search"})

        assert response.status_code == 200
        assert response.context.get("confirm_form") is None
        assert "but not both" in str(response.context["search_form"].non_field_errors())


def confirm_post(phone_number, unlock_user_id, disable_active=True):
    data = {
        "phone_number": phone_number,
        "user_id": "",
        "unlock_user_id": str(unlock_user_id),
        "confirm": "Unlock and generate backup code",
    }
    if disable_active:
        data["disable_current_active_user"] = "on"
    return data


def extract_backup_code(response):
    backup_code = response.context["backup_code"]
    assert BACKUP_CODE_RE.fullmatch(backup_code), backup_code
    return backup_code


@pytest.mark.django_db
class TestUnlockPageConfirm:
    def test_unlock_activates_the_user_and_returns_a_working_code(self, su_client, unlock_url):
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True, failed_backup_code_attempts=3)

        response = su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        assert response.status_code == 200
        backup_code = extract_backup_code(response)
        locked.refresh_from_db()
        assert locked.is_locked is False
        assert locked.is_active is True
        assert locked.failed_backup_code_attempts == 0
        assert locked.check_recovery_pin(backup_code) is True

    def test_renders_the_success_panel_with_a_fresh_search_form(self, su_client, unlock_url):
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        response = su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        assert response.status_code == 200
        backup_code = extract_backup_code(response)
        assert response.context["unlocked_user"].pk == locked.pk
        assert response.context.get("confirm_form") is None
        assert not response.context["search_form"].is_bound
        content = response.content.decode()
        assert backup_code in content
        assert locked.username in content

    def test_prior_active_account_is_deactivated(self, su_client, unlock_url):
        active = UserFactory(phone_number=PHONE)
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        active.refresh_from_db()
        assert active.is_active is False

    def test_confirm_replay_finds_no_candidates_and_is_a_no_op(self, su_client, unlock_url):
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        su_client.post(unlock_url, confirm_post(PHONE, locked.pk))
        locked.refresh_from_db()
        pin_after_first_unlock = locked.recovery_pin

        response = su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        assert response.status_code == 200
        assert response.context.get("confirm_form") is None
        assert "No locked account matches that search." in str(response.context["search_form"].non_field_errors())
        locked.refresh_from_db()
        assert locked.recovery_pin == pin_after_first_unlock

    def test_email_collision_with_a_different_active_account_is_rejected(self, su_client, unlock_url):
        UserFactory(phone_number="+27829998888", email="dup@example.com")
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True, email="dup@example.com")

        response = su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        assert response.status_code == 200
        assert "dup@example.com" in str(response.context["confirm_form"].non_field_errors())
        locked.refresh_from_db()
        assert locked.is_active is False
        assert locked.is_locked is True

    def test_unchecked_box_with_an_active_account_changes_nothing(self, su_client, unlock_url):
        active = UserFactory(phone_number=PHONE)
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        response = su_client.post(unlock_url, confirm_post(PHONE, locked.pk, disable_active=False))

        assert response.status_code == 200
        assert "must be deactivated" in str(response.context["confirm_form"].non_field_errors())
        active.refresh_from_db()
        locked.refresh_from_db()
        assert active.is_active is True
        assert locked.is_active is False
        assert locked.is_locked is True

    def test_already_active_user_id_is_rejected(self, su_client, unlock_url):
        active = UserFactory(phone_number=PHONE)
        UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        response = su_client.post(unlock_url, confirm_post(PHONE, active.pk))

        assert response.status_code == 200
        assert "unlock_user_id" in response.context["confirm_form"].errors

    def test_backup_code_is_not_persisted_in_plaintext(self, su_client, unlock_url):
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        response = su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        backup_code = extract_backup_code(response)
        locked.refresh_from_db()
        assert backup_code not in locked.recovery_pin
        assert not LogEntry.objects.filter(change_message__contains=backup_code).exists()
        assert all(backup_code not in morsel.value for morsel in response.cookies.values())


@pytest.mark.django_db
class TestUnlockPageAuditLog:
    def _entries_for(self, user):
        content_type = ContentType.objects.get_for_model(ConnectUser)
        return LogEntry.objects.filter(content_type=content_type, object_id=str(user.pk))

    def test_logs_the_unlock(self, su_client, superuser, unlock_url):
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        entry = self._entries_for(locked).get()
        assert entry.user_id == superuser.pk
        assert entry.action_flag == CHANGE
        assert entry.change_message == "Unlocked user and generated a new backup code"

    def test_logs_the_deactivation(self, su_client, superuser, unlock_url):
        active = UserFactory(phone_number=PHONE)
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        entry = self._entries_for(active).get()
        assert entry.user_id == superuser.pk
        assert entry.change_message == f"Deactivated in favour of unlocked user {locked.pk}"

    def test_no_deactivation_entry_when_there_was_no_active_account(self, su_client, unlock_url):
        locked = UserFactory(phone_number=PHONE, is_active=False, is_locked=True)

        su_client.post(unlock_url, confirm_post(PHONE, locked.pk))

        assert LogEntry.objects.count() == 1


@pytest.mark.django_db
class TestAdminIndexButton:
    def test_superuser_sees_the_button(self, su_client, unlock_url):
        response = su_client.get(reverse("admin:index"))

        assert response.status_code == 200
        assert unlock_url in response.content.decode()

    def test_staff_non_superuser_does_not(self, client, unlock_url):
        staff = UserFactory(phone_number="+27821110002", is_staff=True)
        client.force_login(staff, backend=MODEL_BACKEND)

        response = client.get(reverse("admin:index"))

        assert response.status_code == 200
        assert unlock_url not in response.content.decode()

    def test_the_stock_app_list_is_still_rendered(self, su_client):
        response = su_client.get(reverse("admin:index"))

        assert "app_list" in response.context
        assert 'id="content-main"' in response.content.decode()

    def test_the_button_sits_in_the_header_beside_the_site_name(self, su_client, unlock_url):
        response = su_client.get(reverse("admin:index"))
        html = response.content.decode()

        # The branding block's {{ block.super }} must still render Django's own site name...
        assert 'id="site-name"' in html
        # ...and the button belongs in the header, ahead of the app list, not below it.
        assert html.index(unlock_url) < html.index('id="content-main"')

    def test_other_admin_pages_keep_the_stock_header(self, su_client, unlock_url):
        response = su_client.get(reverse("admin:users_connectuser_changelist"))

        assert response.status_code == 200
        assert unlock_url not in response.content.decode()
