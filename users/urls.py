from django.urls import path

from . import views

urlpatterns = [
    path('', views.test, name='test'),
    path('register', views.register, name='register'),
    path('login', views.login, name='login')
]
