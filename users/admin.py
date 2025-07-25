from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

from .models import ConfigurationSession, ConnectUser


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
