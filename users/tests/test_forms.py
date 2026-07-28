import pytest

from users.factories import UserFactory
from users.forms import UnlockUserConfirmForm, UnlockUserSearchForm

PHONE = "+27821234567"


class TestUnlockUserSearchForm:
    def test_phone_number_only_is_valid(self):
        form = UnlockUserSearchForm({"phone_number": PHONE})

        assert form.is_valid(), form.errors

    def test_user_id_only_is_valid(self):
        form = UnlockUserSearchForm({"user_id": "42"})

        assert form.is_valid(), form.errors

    def test_neither_is_invalid(self):
        form = UnlockUserSearchForm({})

        assert not form.is_valid()
        assert "either a phone number or a user ID" in str(form.non_field_errors())

    def test_both_is_invalid(self):
        form = UnlockUserSearchForm({"phone_number": PHONE, "user_id": "42"})

        assert not form.is_valid()
        assert "either a phone number or a user ID" in str(form.non_field_errors())

    def test_unparseable_phone_number_is_a_field_error(self):
        form = UnlockUserSearchForm({"phone_number": "not a number"})

        assert not form.is_valid()
        assert "phone_number" in form.errors

    def test_phone_number_is_normalised_to_e164(self):
        form = UnlockUserSearchForm({"phone_number": "+27 82 123 4567"})

        assert form.is_valid(), form.errors
        assert str(form.cleaned_data["phone_number"]) == PHONE


@pytest.mark.django_db
class TestUnlockUserConfirmForm:
    def test_valid_selection_exposes_the_user(self):
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)
        form = UnlockUserConfirmForm(
            {"unlock_user_id": str(locked.pk), "disable_current_active_user": "on"},
            candidates=[locked],
        )

        assert form.is_valid(), form.errors
        assert form.selected_user.pk == locked.pk

    def test_id_outside_the_candidate_list_is_rejected(self):
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)
        other = UserFactory.create(phone_number="+27829998888", is_active=False, is_locked=True)
        form = UnlockUserConfirmForm({"unlock_user_id": str(other.pk)}, candidates=[locked])

        assert not form.is_valid()
        assert "unlock_user_id" in form.errors

    def test_unchecked_box_with_an_active_account_is_rejected(self):
        UserFactory.create(phone_number=PHONE)
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)
        form = UnlockUserConfirmForm({"unlock_user_id": str(locked.pk)}, candidates=[locked])

        assert not form.is_valid()
        assert "must be deactivated" in str(form.non_field_errors())

    def test_unchecked_box_with_no_active_account_is_fine(self):
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)
        form = UnlockUserConfirmForm({"unlock_user_id": str(locked.pk)}, candidates=[locked])

        assert form.is_valid(), form.errors
        assert form.cleaned_data["disable_current_active_user"] is False

    def test_unbound_form_defaults_the_checkbox_to_on(self):
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)
        form = UnlockUserConfirmForm(candidates=[locked])

        assert form.fields["disable_current_active_user"].initial is True

    def test_rejects_email_collision_with_a_different_active_user(self):
        UserFactory.create(phone_number="+27829998888", email="dup@example.com")
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True, email="dup@example.com")
        form = UnlockUserConfirmForm(
            {"unlock_user_id": str(locked.pk), "disable_current_active_user": "on"},
            candidates=[locked],
        )

        assert not form.is_valid()
        assert "dup@example.com" in str(form.non_field_errors())

    def test_does_not_reject_email_collision_with_the_account_being_deactivated(self):
        active = UserFactory.create(phone_number=PHONE, email="dup@example.com")
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True, email="dup@example.com")
        form = UnlockUserConfirmForm(
            {"unlock_user_id": str(locked.pk), "disable_current_active_user": "on"},
            candidates=[locked],
        )

        assert form.is_valid(), form.errors
        assert active.pk != locked.pk

    def test_does_not_reject_blank_email(self):
        UserFactory.create(phone_number="+27829998888", email="")
        locked = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True, email="")
        form = UnlockUserConfirmForm(
            {"unlock_user_id": str(locked.pk), "disable_current_active_user": "on"},
            candidates=[locked],
        )

        assert form.is_valid(), form.errors


@pytest.mark.django_db
class TestCandidateLabel:
    def _label_for(self, user):
        form = UnlockUserConfirmForm(candidates=[user])
        return str(form.fields["unlock_user_id"].choices[0][1])

    def test_identifies_the_account_by_username_name_and_join_date(self):
        user = UserFactory.create(
            username="thandiwe.mokoena",
            name="Thandiwe Mokoena",
            phone_number=PHONE,
            is_active=False,
            is_locked=True,
        )

        label = self._label_for(user)

        assert "thandiwe.mokoena" in label
        assert "Thandiwe Mokoena" in label
        assert f"joined {user.date_joined.date()}" in label

    def test_omits_the_database_id_and_last_login(self):
        user = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        label = self._label_for(user)

        assert "last login" not in label
        assert f"(id {user.pk})" not in label

    def test_shows_the_locked_and_active_status(self):
        user = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=True)

        assert "(inactive, locked)" in self._label_for(user)

    def test_distinguishes_an_inactive_account_that_is_not_locked(self):
        user = UserFactory.create(phone_number=PHONE, is_active=False, is_locked=False)

        assert "(inactive, not locked)" in self._label_for(user)
