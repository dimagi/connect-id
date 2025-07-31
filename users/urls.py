from django.urls import path

from payments import views as payment_views

from . import views

urlpatterns = [
    path("", views.test, name="test"),
    path("register", views.register, name="register"),
    path("login", views.login, name="login"),
    path("validate_phone", views.validate_phone, name="validate_phone"),
    path("validate_firebase_id_token", views.validate_firebase_id_token, name="validate_firebase_id_token"),
    path("confirm_otp", views.confirm_otp, name="confirm_otp"),
    path("send_session_otp", views.send_session_otp, name="send_session_otp"),
    path("confirm_session_otp", views.confirm_session_otp, name="confirm_session_otp"),
    path("validate_secondary_phone", views.validate_secondary_phone, name="validate_secondary_phone"),
    path("confirm_secondary_otp", views.confirm_secondary_otp, name="confirm_secondary_otp"),
    path("recover", views.recover_account, name="recover_account"),
    path("recover/confirm_otp", views.confirm_recovery_otp, name="confirm_recovery_otp"),
    path("recover/secondary", views.recover_secondary_phone, name="recover_secondary_phone"),
    path("recover/confirm_secondary_otp", views.confirm_secondary_recovery_otp, name="confirm_secondary_recovery_otp"),
    path("recover/reset_password", views.reset_password, name="reset_password"),
    path("recover/confirm_password", views.confirm_password, name="confirm_password"),
    path("phone_available", views.phone_available, name="phone_available"),
    path("change_phone", views.change_phone, name="change_phone"),
    path("change_password", views.change_password, name="change_password"),
    path("update_profile", views.update_profile, name="update_profile"),
    path("fetch_users", views.FetchUsers.as_view(), name="fetch_users"),
    path("heartbeat", views.heartbeat, name="heartbeat"),
    path("demo_users", views.GetDemoUsers.as_view(), name="demo_users"),
    path("recover/confirm_pin", views.confirm_recovery_pin, name="confirm_recovery_pin"),
    path("recover/confirm_backup_code", views.confirm_backup_code, name="confirm_backup_code"),
    path("set_recovery_pin", views.set_recovery_pin, name="set_recovery_pin"),
    path("filter_users", views.FilterUsers.as_view(), name="filter_users"),
    path("add_credential", views.AddCredential.as_view(), name="add_credential"),
    path("accept_credential/<slug:invite_id>", views.accept_credential, name="accept_credential"),
    path("fetch_db_key", views.fetch_db_key, name="fetch_db_key"),
    path("recover/initiate_deactivation", views.initiate_deactivation, name="initiate_deactivation"),
    path("recover/confirm_deactivation", views.confirm_deactivation, name="confirm_deactivation"),
    path(
        "profile/payment_phone_number", payment_views.update_payment_profile_phone, name="update_payment_profile_phone"
    ),
    path("profile/confirm_payment_otp", payment_views.confirm_payment_profile_otp, name="confirm_payment_profile_otp"),
    path("fetch_payment_phone_numbers", payment_views.FetchPhoneNumbers.as_view(), name="fetch_payment_phone_numbers"),
    path(
        "validate_payment_phone_numbers",
        payment_views.ValidatePhoneNumbers.as_view(),
        name="validate_payment_phone_numbers",
    ),
    path("forward_hq_invite", views.ForwardHQInvite.as_view(), name="forward_hq_invite"),
    path("confirm_hq_invite", views.ConfirmHQInviteCallback.as_view(), name="confirm_hq_invite"),
    path("fetch_user_counts", views.FetchUserCounts.as_view(), name="fetch_user_counts"),
    path("check_name", views.check_user_similarity, name="check_user_similarity"),
    path("start_configuration", views.start_device_configuration, name="start_device_configuration"),
    path("complete_profile", views.complete_profile, name="complete_profile"),
    path("report_integrity", views.report_integrity, name="report_integrity"),
]
