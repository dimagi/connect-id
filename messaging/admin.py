from django.contrib import admin

from .models import MessageServer


@admin.register(MessageServer)
class MessageServerAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "key_url",
        "callback_url",
        "delivery_url",
        "consent_url",
        "server_id",
        "secret_key",
    )
    search_fields = ("name",)
