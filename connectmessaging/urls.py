from django.urls import path

import connectmessaging.views as views


app_name = 'connectmessaging'

urlpatterns = [
    path('create_channel/', views.CreateChannelView.as_view(), name='create_channel'),
    path('send_message/', views.SendMessageView.as_view(), name='send_message'),
    path('update_consent/', views.UpdateConsentView.as_view(), name='update_consent'),
    path('retrieve_messages/:connect_user_id', views.RetrieveMessagesView.as_view(), name='retrieve_messages'),
    path('update_received/', views.UpdateReceivedView.as_view(), name='update_received'),
]
