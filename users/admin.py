from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import ConnectUser

admin.site.register(ConnectUser, UserAdmin)
