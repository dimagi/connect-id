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
    path('recover', views.recover_account, name='recover_account'),
    path('recover/confirm_otp', views.confirm_recovery_otp, name='confirm_recovery_otp'),
    path('recover/secondary', views.recover_secondary_phone , name='recover_secondary_phone'),
    path('recover/confirm_secondary_otp', views.confirm_secondary_recovery_otp , name='confirm_secondary_recovery_otp'),
    path('recover/reset_password', views.reset_password , name='reset_password'),
    path('recover/confirm_password', views.confirm_password, name='confirm_password'),
    path('phone_available', views.phone_available, name='phone_available'),
    path('change_phone', views.change_phone, name='change_phone'),
    path('change_password', views.change_password, name='change_password'),
    path('update_profile', views.update_profile, name='update_profile'),
    path('fetch_users', views.FetchUsers.as_view(), name='fetch_users'),
    path('heartbeat', views.heartbeat, name='heartbeat'),
    path('demo_users', views.GetDemoUsers.as_view(), name='demo_users'),
    path('recover/confirm_pin', views.confirm_recovery_pin, name='confirm_recovery_pin'),
    path('set_recovery_pin', views.set_recovery_pin, name='set_recovery_pin'),
    path('filter_users', views.FilterUsers.as_view(), name='filter_users'),
    path('add_credential', views.AddCredential.as_view(), name='add_credential'),
    path('accept_credential/<slug:invite_id>', views.accept_credential, name='accept_credential'),
    path('fetch_credentials', views.FetchCredentials.as_view(), name='fetch_credentials'),
]
