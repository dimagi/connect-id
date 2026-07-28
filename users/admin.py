from django.contrib import admin
from django.contrib.admin.models import CHANGE, LogEntry
from django.contrib.auth.admin import UserAdmin
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.template.response import TemplateResponse
from django.urls import path
from django.utils.translation import gettext_lazy as _

from .forms import UnlockUserConfirmForm, UnlockUserSearchForm
from .models import ConfigurationSession, ConnectUser, DeviceIntegritySample, IssuingAuthority, ServerKeys
from .unlock import find_unlock_candidates, generate_backup_code, get_active_user, unlock_user


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

        context = {
            **self.admin_site.each_context(request),
            "title": "Unlock user",
            "opts": self.model._meta,
        }

        if request.method != "POST":
            context["search_form"] = UnlockUserSearchForm()
            return TemplateResponse(request, self.unlock_template, context)

        search_form = UnlockUserSearchForm(request.POST)
        context["search_form"] = search_form
        if not search_form.is_valid():
            return TemplateResponse(request, self.unlock_template, context)

        candidates = find_unlock_candidates(
            phone_number=search_form.cleaned_data.get("phone_number"),
            user_id=search_form.cleaned_data.get("user_id"),
        )
        if not candidates:
            search_form.add_error(None, "No locked account matches that search.")
            return TemplateResponse(request, self.unlock_template, context)

        active_user = get_active_user(candidates[0].phone_number)
        context["active_user"] = active_user

        if "confirm" not in request.POST:
            context["confirm_form"] = UnlockUserConfirmForm(candidates=candidates)
            return TemplateResponse(request, self.unlock_template, context)

        confirm_form = UnlockUserConfirmForm(request.POST, candidates=candidates)
        context["confirm_form"] = confirm_form
        if not confirm_form.is_valid():
            return TemplateResponse(request, self.unlock_template, context)

        user = confirm_form.selected_user
        disable_active = confirm_form.cleaned_data["disable_current_active_user"]
        with transaction.atomic():
            unlock_user(user, disable_current_active_user=disable_active)
            backup_code = generate_backup_code(user)
            if disable_active and active_user is not None:
                self._log_unlock(request, active_user, f"Deactivated in favour of unlocked user {user.pk}")
            self._log_unlock(request, user, "Unlocked user and generated a new backup code")

        # The backup code is only ever shown here, once, in the rendered response. It must
        # never enter the messages framework (signed but not encrypted cookie storage) or
        # get logged.
        context["confirm_form"] = None
        context["search_form"] = UnlockUserSearchForm()
        context["unlocked_user"] = user
        context["backup_code"] = backup_code
        return TemplateResponse(request, self.unlock_template, context)

    def _log_unlock(self, request, user, message):
        LogEntry.objects.log_action(
            user_id=request.user.pk,
            content_type_id=ContentType.objects.get_for_model(ConnectUser).pk,
            object_id=user.pk,
            object_repr=str(user),
            action_flag=CHANGE,
            change_message=message,
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


# Adds the "Unlock user" button to the admin index. Set here because users/admin.py is
# imported by admin autodiscovery.
admin.site.index_template = "admin/index_with_unlock.html"
