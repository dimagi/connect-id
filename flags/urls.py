from django.urls import path

from flags.views import TogglesView

urlpatterns = [
    path("", TogglesView.as_view(), name="toggles"),
]
