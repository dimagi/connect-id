from django.urls import path

from messaging import views

app_name = 'messaging'

urlpatterns = [
    path('send/', views.SendMessage.as_view(), name='send_message'),
]
