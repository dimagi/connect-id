from django.contrib import admin

from .models import Channel, Message, MessageServer


@admin.register(MessageServer)
class MessageServerAdmin(admin.ModelAdmin):
    list_display = ("name", "key_url", "callback_url", "delivery_url", "consent_url", "server_credentials")
    search_fields = ("name",)


@admin.register(Channel)
class ChannelAdmin(admin.ModelAdmin):
    list_display = ("channel_source", "channel_name", "connect_user")
    search_fields = ("connect_user__phone_number", "connect_user__username")


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("channel", "timestamp", "received", "direction", "status")
    search_fields = ("channel__connect_user__phone_number", "channel__connect_user__username")
