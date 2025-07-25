from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

from .models import ConfigurationSession, ConnectUser, IssuingAuthority, IssuingCredentialsAuth


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
    list_display = ("username", "phone_number", "name", "is_staff")
    search_fields = ("username", "name", "phone_number")


@admin.register(ConfigurationSession)
class ConfigurationSessionAdmin(admin.ModelAdmin):
    list_display = ("phone_number", "created")
    search_fields = ("phone_number",)


@admin.register(IssuingAuthority)
class IssuingAuthorityAdmin(admin.ModelAdmin):
    list_display = ("issuing_authority", "issuer_environment", "issuer_credentials")


@admin.register(IssuingCredentialsAuth)
class IssuingCredentialsAuthAdmin(admin.ModelAdmin):
    list_display = ("name", "client_id", "secret_key")
    search_fields = ("name", "client_id")

    def save_model(self, request, obj, form, change):
        if "secret_key" in form.cleaned_data:
            secret_key = form.cleaned_data["secret_key"]
            obj.set_secret_key(secret_key)
        super().save_model(request, obj, form, change)
