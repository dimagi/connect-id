from django.urls import path

from messaging import views

app_name = "messaging"

urlpatterns = [
    path("send/", views.SendMessage.as_view(), name="send_message"),
    path("send_bulk/", views.SendMessageBulk.as_view(), name="send_message_bulk"),
    path("create_channel/", views.CreateChannelView.as_view(), name="create_channel"),
    path("send_message/", views.SendMessageView.as_view(), name="post_message"),
    path("send_fcm/", views.SendFcmNotificationView.as_view(), name="send_fcm"),
    path("update_consent/", views.UpdateConsentView.as_view(), name="update_consent"),
    path(
        "retrieve_messages/",
        views.RetrieveMessageView.as_view(),
        name="retrieve_messages",
    ),
    path(
        "update_received/", views.UpdateReceivedView.as_view(), name="update_received"
    ),
]
