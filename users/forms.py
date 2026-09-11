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
        # The form owns this rather than the view: it is what the checkbox is about, what
        # clean() validates against, and what the template warns on, so one lookup serves all
        # three. Candidates always share a phone number — the id path yields exactly one.
        self.active_user = get_active_user(candidates[0].phone_number) if candidates else None
        self.fields["unlock_user_id"].choices = [(user.pk, _candidate_label(user)) for user in candidates]
        if len(candidates) == 1:
            self.fields["unlock_user_id"].initial = candidates[0].pk

    @property
    def selected_user(self):
        """The chosen candidate, or None until unlock_user_id has validated."""
        return self.candidates.get(self.cleaned_data.get("unlock_user_id"))

    def clean_unlock_user_id(self):
        # ChoiceField has already checked membership of self.candidates.
        return int(self.cleaned_data["unlock_user_id"])

    def clean(self):
        cleaned_data = super().clean()
        selected_user = self.selected_user
        if selected_user is None:
            return cleaned_data

        disable_current_active_user = cleaned_data.get("disable_current_active_user")

        if not disable_current_active_user and self.active_user is not None:
            raise forms.ValidationError(
                "There is already an active account on this phone number. Only one account per phone "
                "number can be active, so the current one must be deactivated."
            )

        if selected_user.email:
            # Accounts that will not be active once this unlock commits, so they cannot conflict
            # over the email even if they hold it right now.
            leaving_active = {selected_user.pk}
            if disable_current_active_user and self.active_user is not None:
                leaving_active.add(self.active_user.pk)
            conflicting_username = (
                ConnectUser.objects.filter(email=selected_user.email, is_active=True)
                .exclude(pk__in=leaving_active)
                .values_list("username", flat=True)
                .first()
            )
            if conflicting_username is not None:
                raise forms.ValidationError(
                    f"The email address {selected_user.email} is already in use by the active account "
                    f"{conflicting_username}. That account's email must change before this one can "
                    "be unlocked."
                )

        return cleaned_data


def _candidate_label(user):
    # Candidates are always inactive, but the user-ID path also admits accounts that are
    # not locked, so both flags are worth stating rather than assuming.
    status = f"{'active' if user.is_active else 'inactive'}, {'locked' if user.is_locked else 'not locked'}"
    return format_html(
        '<strong>{}</strong> &mdash; {} &mdash; joined {} <span class="unlock-status">({})</span>',
        user.username,
        user.name or "no name",
        user.date_joined.date(),
        status,
    )
