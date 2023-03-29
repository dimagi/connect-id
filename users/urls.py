from django.urls import path

from . import views

urlpatterns = [
    path('', views.test, name='test'),
    path('register', views.register, name='register'),
    path('login', views.login, name='login'),
    path('validate_phone', views.validate_phone, name='validate_phone'),
    path('confirm_otp', views.confirm_otp, name='confirm_otp'),
]
