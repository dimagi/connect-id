from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.template.response import TemplateResponse
from django.urls import path
from django.utils.translation import gettext_lazy as _

from .forms import UnlockUserConfirmForm, UnlockUserSearchForm
from .models import ConfigurationSession, ConnectUser, DeviceIntegritySample, IssuingAuthority, ServerKeys
from .unlock import find_unlock_candidates, unlock_and_issue_backup_code


@admin.register(ConnectUser)
class ConnectUserAdmin(UserAdmin):
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (_("Personal info"), {"fields": ("name", "email", "phone_number")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
        (_("Extras"), {"fields": ("is_locked", "device_security")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "fields": ("username", "password1", "password2", "phone_number"),
            },
        ),
    )
    list_display = ("username", "phone_number", "name", "is_staff")
    search_fields = ("username", "name", "phone_number")

    unlock_template = "admin/users/connectuser/unlock_user.html"

    def get_urls(self):
        # Must precede super()'s catch-all "<path:object_id>/" pattern.
        custom_urls = [
            path(
                "unlock/",
                self.admin_site.admin_view(self.unlock_user_view),
                name="users_connectuser_unlock",
            ),
        ]
        return custom_urls + super().get_urls()

    def unlock_user_view(self, request):
        if not request.user.is_superuser:
            raise PermissionDenied

        base_context = {**self.admin_site.each_context(request), "title": "Unlock user"}

        def render(**state):
            # Each return states the whole render state, so no branch depends on what an
            # earlier one put in the context. The template keys off confirm_form.
            return TemplateResponse(request, self.unlock_template, {**base_context, **state})

        if request.method != "POST":
            return render(search_form=UnlockUserSearchForm())

        search_form = UnlockUserSearchForm(request.POST)
        if not search_form.is_valid():
            return render(search_form=search_form)

        candidates = find_unlock_candidates(
            phone_number=search_form.cleaned_data.get("phone_number"),
            user_id=search_form.cleaned_data.get("user_id"),
        )
        if not candidates:
            search_form.add_error(None, "No locked account matches that search.")
            return render(search_form=search_form)

        if "confirm" not in request.POST:
            return render(search_form=search_form, confirm_form=UnlockUserConfirmForm(candidates=candidates))

        confirm_form = UnlockUserConfirmForm(request.POST, candidates=candidates)
        if not confirm_form.is_valid():
            return render(search_form=search_form, confirm_form=confirm_form)

        user = confirm_form.selected_user
        active_user = confirm_form.active_user
        disable_active = confirm_form.cleaned_data["disable_current_active_user"]
        with transaction.atomic():
            backup_code = unlock_and_issue_backup_code(user, disable_current_active_user=disable_active)
            if disable_active and active_user is not None:
                self.log_change(request, active_user, f"Deactivated in favour of unlocked user {user.pk}")
            self.log_change(request, user, "Unlocked user and generated a new backup code")

        # The backup code is only ever shown here, once, in the rendered response. It must
        # never enter the messages framework (signed but not encrypted cookie storage) or
        # get logged.
        return render(
            search_form=UnlockUserSearchForm(),
            unlocked_user=user,
            backup_code=backup_code,
        )


@admin.register(ConfigurationSession)
class ConfigurationSessionAdmin(admin.ModelAdmin):
    list_display = ("phone_number", "device_id", "created")
    search_fields = ("phone_number", "device_id")


@admin.register(IssuingAuthority)
class IssuingAuthorityAdmin(admin.ModelAdmin):
    list_display = ("issuing_authority", "issuer_environment", "server_credentials")


@admin.register(ServerKeys)
class ServerKeysAdmin(admin.ModelAdmin):
    list_display = ("name", "client_id", "secret_key")
    search_fields = ("name", "client_id")

    def save_model(self, request, obj, form, change):
        if "secret_key" in form.cleaned_data:
            secret_key = form.cleaned_data["secret_key"]
            obj.secret_key = secret_key
        super().save_model(request, obj, form, change)


@admin.register(DeviceIntegritySample)
class DeviceIntegritySampleAdmin(admin.ModelAdmin):
    list_display = ("request_id", "device_id", "passed", "created")
    search_fields = ("request_id", "device_id", "passed", "created")
    list_filter = ("device_id", "passed")
