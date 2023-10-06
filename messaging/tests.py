import base64
import json
from unittest import mock

import pytest
from django.urls import reverse
from firebase_admin import messaging
from oauth2_provider.models import Application


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

    with mock.patch("fcm_django.models.messaging.send") as mock_send_message:
        response = authed_client.post(url, data={
            "username": fcm_device.user.username,
            "body": "test message",
            "data": {"test": "data"},
        }, content_type="application/json")
        assert response.status_code == 200, response.content
        mock_send_message.assert_called_once()
        message = mock_send_message.call_args_list[0].args[0]
        assert json.loads(str(message)) == {
            "data": {"test": "data"}, "notification": {"body": "test message"}, "token": "testregid"
        }


def test_send_message_bulk(authed_client, fcm_device):
    url = reverse('messaging:send_message_bulk')

    with mock.patch("fcm_django.models.messaging.send_all") as mock_send_message:
        mock_send_message.return_value = messaging.BatchResponse([
            messaging.SendResponse({'name': 'message_id_1'}, None),
        ])
        response = authed_client.post(url, data={
            "messages": [
                {
                    "usernames": [fcm_device.user.username, fcm_device.user.username],
                    "title": "test title",
                    "body": "test message",
                    "data": {"test": "data"},
                },
                {
                    "usernames": ['nonexistent-user'],
                    "title": "test title",
                    "body": "test message",
                    "data": {"test": "data"},
                }
            ]
        }, content_type="application/json")

        assert response.status_code == 200, response.content
        mock_send_message.assert_called_once()
        messages = mock_send_message.call_args_list[0].args[0]
        assert len(messages) == 1
        assert json.loads(str(messages[0])) == {
            "data": {"test": "data"},
            "notification": {"body": "test message", "title": "test title"},
            "token": "testregid"
        }

        results = response.json()['results']
        assert results == [
            {'status': 'success', 'username': 'testuser'},
            {'status': 'deactivated', 'username': 'nonexistent-user'},
        ]
