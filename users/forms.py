from django import forms
from django.utils.html import format_html
from phonenumber_field.formfields import PhoneNumberField

from users.models import ConnectUser
from users.unlock import get_active_user


class UnlockUserSearchForm(forms.Form):
    phone_number = PhoneNumberField(
        required=False,
        help_text="Include the country code, for example +27821234567.",
    )
    user_id = forms.IntegerField(
        required=False,
        label="User ID",
        help_text="Use this when several locked accounts share a phone number.",
    )

    def clean(self):
        cleaned_data = super().clean()
        phone_number = cleaned_data.get("phone_number")
        user_id = cleaned_data.get("user_id")
        if bool(phone_number) == bool(user_id):
            raise forms.ValidationError("Provide either a phone number or a user ID, but not both.")
        return cleaned_data


class UnlockUserConfirmForm(forms.Form):
    unlock_user_id = forms.ChoiceField(
        widget=forms.RadioSelect,
        label="Account to unlock",
    )
    disable_current_active_user = forms.BooleanField(
        required=False,
        initial=True,
        label="Deactivate the currently active account",
    )

    def __init__(self, data=None, *, candidates, **kwargs):
        super().__init__(data, **kwargs)
        self.candidates = {user.pk: user for user in candidates}
        self.selected_user = None
        self.fields["unlock_user_id"].choices = [(user.pk, _candidate_label(user)) for user in candidates]
        if len(candidates) == 1:
            self.fields["unlock_user_id"].initial = candidates[0].pk

    def clean_unlock_user_id(self):
        # ChoiceField has already checked membership of self.candidates.
        user_id = int(self.cleaned_data["unlock_user_id"])
        self.selected_user = self.candidates[user_id]
        return user_id

    def clean(self):
        cleaned_data = super().clean()
        if self.selected_user is None:
            return cleaned_data

        disable_current_active_user = cleaned_data.get("disable_current_active_user")
        active_user = get_active_user(self.selected_user.phone_number)

        if not disable_current_active_user:
            if active_user is not None:
                raise forms.ValidationError(
                    "There is already an active account on this phone number. Only one account per phone "
                    "number can be active, so the current one must be deactivated."
                )

        if self.selected_user.email:
            email_conflicts = ConnectUser.objects.filter(email=self.selected_user.email, is_active=True).exclude(
                pk=self.selected_user.pk
            )
            if active_user is not None and disable_current_active_user:
                # This account is about to be deactivated as part of this same unlock, so it
                # isn't a real conflict even though it currently holds the email.
                email_conflicts = email_conflicts.exclude(pk=active_user.pk)
            conflicting_user = email_conflicts.first()
            if conflicting_user is not None:
                raise forms.ValidationError(
                    f"The email address {self.selected_user.email} is already in use by the active account "
                    f"{conflicting_user.username}. That account's email must change before this one can "
                    "be unlocked."
                )

        return cleaned_data


def _candidate_label(user):
    return format_html(
        '<strong>{}</strong> &mdash; {} &mdash; joined {} <span class="unlock-status">({})</span>',
        user.username,
        user.name or "no name",
        user.date_joined.date(),
        _candidate_status(user),
    )


def _candidate_status(user):
    # Candidates are always inactive, but the user-ID path also admits accounts that are
    # not locked, so both flags are worth stating rather than assuming.
    active = "active" if user.is_active else "inactive"
    locked = "locked" if user.is_locked else "not locked"
    return f"{active}, {locked}"
