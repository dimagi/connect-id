from django.urls import path

from . import views

urlpatterns = [
    path('', views.test, name='test'),
    path('register', views.register, name='register'),
    path('login', views.login, name='login'),
    path('validate_phone', views.validate_phone, name='validate_phone'),
    path('confirm_otp', views.confirm_otp, name='confirm_otp'),
    path('validate_secondary_phone', views.validate_secondary_phone, name='validate_secondary_phone'),
    path('confirm_secondary_otp', views.confirm_secondary_otp, name='confirm_secondary_otp'),
    path('recover_account', views.recover_account, name='recover_account'),
    path('confirm_recovery_otp', views.confirm_recovery_otp, name='confirm_recovery_otp'),
    path('recover_secondary_phone', views.recover_secondary_phone , name='recover_secondary_phone'),
    path('confirm_secondary_recovery_otp', views.confirm_secondary_recovery_otp , name='confirm_secondary_recovery_otp'),
    path('reset_password', views.reset_password , name='reset_password'),
]
