from django.contrib import admin
from waffle.admin import FlagAdmin

from flags.models import Flag

admin.site.register(Flag, FlagAdmin)
