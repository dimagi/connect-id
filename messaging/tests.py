import base64
import json
from unittest import mock

import pytest
from django.urls import reverse
from firebase_admin import messaging
from oauth2_provider.models import Application

from users.factories import FCMDeviceFactory


@pytest.fixture
def oauth_app(user):
    application = Application(
        name="Test Application",
        redirect_uris="http://localhost",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
    )
    application.raw_client_secret = application.client_secret
    application.save()
    return application


@pytest.fixture
def authed_client(client, oauth_app):
    auth = f'{oauth_app.client_id}:{oauth_app.raw_client_secret}'.encode('utf-8')
    credentials = base64.b64encode(auth).decode('utf-8')
    client.defaults['HTTP_AUTHORIZATION'] = 'Basic ' + credentials
    return client


def test_send_message(authed_client, fcm_device):
    url = reverse('messaging:send_message')

    with mock.patch("fcm_django.models.messaging.send_all", wraps=_fake_send) as mock_send_message:
        response = authed_client.post(url, data={
            "username": fcm_device.user.username,
            "body": "test message",
            "data": {"test": "data"},
        }, content_type="application/json")
        assert response.status_code == 200, response.content
        assert response.json() == {
            'all_success': True,
            'responses': [{'username': fcm_device.user.username, 'status': 'success'}]
        }
        mock_send_message.assert_called_once()
        messages = mock_send_message.call_args_list[0].args[0]
        assert len(messages) == 1
        assert json.loads(str(messages[0])) == {
            "data": {"test": "data"}, "notification": {"body": "test message"}, "token": fcm_device.registration_id
        }


def test_send_message_bulk(authed_client, fcm_device):
    url = reverse('messaging:send_message_bulk')

    fcm_device2 = FCMDeviceFactory()
    fcm_device3 = FCMDeviceFactory(active=False)

    with mock.patch("fcm_django.models.messaging.send_all", wraps=_fake_send) as mock_send_message:
        response = authed_client.post(url, data={
            "messages": [
                {
                    "usernames": [fcm_device.user.username, fcm_device.user.username, fcm_device2.user.username],
                    "title": "test title1",
                    "body": "test message1",
                    "data": {"test": "data1"},
                },
                {
                    "usernames": [fcm_device.user.username, 'nonexistent-user', fcm_device3.user.username],
                    "title": "test title2",
                    "body": "test message2",
                    "data": {"test": "data2"},
                }
            ]
        }, content_type="application/json")

        assert response.status_code == 200, response.content
        assert mock_send_message.call_count == 2
        messages = mock_send_message.call_args_list[0].args[0]
        assert len(messages) == 2
        assert json.loads(str(messages[0])) == {
            "data": {"test": "data1"},
            "notification": {"body": "test message1", "title": "test title1"},
            "token": fcm_device.registration_id,
        }

        assert response.json()['all_success'] is False
        results = response.json()['messages']
        assert results == [
            {
                "all_success": True,
                "responses": [
                    {'status': 'success', 'username': fcm_device.user.username},
                    {'status': 'success', 'username': fcm_device2.user.username},
                ]
            },
            {
                "all_success": False,
                "responses": [
                    {'status': 'success', 'username': fcm_device.user.username},
                    {'status': 'deactivated', 'username': 'nonexistent-user'},
                    {'status': 'deactivated', 'username': fcm_device3.user.username},
                ]
            }
        ]


def _fake_send(messages, **kwargs):
    return messaging.BatchResponse([
        messaging.SendResponse({'name': f'message_id_{i}'}, None)
        for i, message in enumerate(messages)
    ])
