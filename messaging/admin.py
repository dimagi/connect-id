from django.contrib import admin

from .models import MessageServer


@admin.register(MessageServer)
class MessageServerAdmin(admin.ModelAdmin):
    list_display = ('name', 'oauth_application', 'key_url', 'callback_url', 'delivery_url', 'consent_url')
    search_fields = ('name',)
    list_filter = ('oauth_application',)
