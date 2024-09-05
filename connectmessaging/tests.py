import base64
from uuid import uuid4

import pytest
from django.urls import reverse
from oauth2_provider.models import Application
from rest_framework import status

from connectmessaging.factories import ChannelFactory, MessageFactory
from connectmessaging.models import Message, Channel

APPLICATION_JSON = 'application/json'


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


@pytest.fixture
def channel(user, consent=True):
    return ChannelFactory(connect_user=user)


def rest_channel_data(user=None, consent=False):
    return {
        'user_consent': consent,
        "connect_user": user.id if user else None,
        "channel_source": "hq project space",
        'key_url': 'https://example.com/key',
        'callback_url': 'https://example.com/callback',
        'delivery_url': 'https://example.com/delivery'
    }


def rest_message(channel_id=None):
    return {
        "channel": channel_id if channel_id else None,
        "content": b"Hello, World!"
    }


@pytest.mark.django_db
class TestCreateChannelView:
    @staticmethod
    def post_channel_request(client, data, expected_status, expected_error_field=None):
        """
        Helper method to send a POST request to create a channel and check the response.
        """
        url = reverse("connectmessaging:create_channel")
        response = client.post(url, data=data, content_type=APPLICATION_JSON)

        assert response.status_code == expected_status, (
            f"Expected status {expected_status}, but got {response.status_code} - {response.data}"
        )

        if expected_status == status.HTTP_400_BAD_REQUEST and expected_error_field:
            assert expected_error_field in response.data, (
                f"'{expected_error_field}' field should be in response errors: {response.data}"
            )

        return response

    def test_unauthorized_access(self, client, fcm_device):
        data = rest_channel_data(fcm_device.user)
        self.post_channel_request(client, data, status.HTTP_403_FORBIDDEN)

    def test_create_channel_success(self, authed_client, fcm_device):
        data = rest_channel_data(fcm_device.user)
        response = self.post_channel_request(authed_client, data, status.HTTP_201_CREATED)

        assert "channel_id" in response.data, f"'channel_id' not found in response data: {response.data}"
        channel_id = response.data["channel_id"]
        assert Message.objects.filter(message_id=channel_id).exists()

    def test_missing_keys(self, authed_client, fcm_device):
        required_keys = ["connect_user", "key_url", "callback_url", "channel_source", "delivery_url"]
        for key in required_keys:
            data = rest_channel_data(fcm_device.user)
            data.pop(key)
            self.post_channel_request(authed_client, data, status.HTTP_400_BAD_REQUEST, key)


@pytest.mark.django_db
class TestSendMessageView:
    url = reverse("connectmessaging:send_message")

    def test_send_message_success(self, authed_client, channel):
        data = rest_message(channel.channel_id)
        response = authed_client.post(self.url, data)

        assert response.status_code == status.HTTP_201_CREATED, (
            f"Expected status {status.HTTP_201_CREATED}, but got {response.status_code}."
        )
        assert 'message_id' in response.data, (
            "Expected 'message_id' in response data, but it was missing."
        )
        message_id = response.data['message_id']
        assert Message.objects.filter(message_id=message_id).exists()

    def test_send_message_no_consent(self, authed_client, channel):
        channel.user_consent = False
        channel.save()
        data = rest_message(channel.channel_id)
        response = authed_client.post(self.url, data)

        assert response.status_code == status.HTTP_403_FORBIDDEN, (
            f"Expected status {status.HTTP_403_FORBIDDEN}, but got {response.status_code}."
        )

    def test_with_invalid_channel_id(self, authed_client):
        data = rest_message(str(uuid4()))
        response = authed_client.post(self.url, data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST, (
            f"Expected status {status.HTTP_400_BAD_REQUEST}, but got {response.status_code}."
        )
        assert 'channel' in response.data, (
            "Expected 'channel' in response data, but it was missing."
        )


@pytest.mark.django_db
class TestRetrieveMessagesView:
    url = reverse('connectmessaging:retrieve_messages')

    def test_retrieve_messages_success(self, authed_client, fcm_device):
        ch = ChannelFactory.create(connect_user=fcm_device.user)
        MessageFactory.create_batch(10, channel=ch)

        response = authed_client.get(self.url)

        assert response.status_code == status.HTTP_200_OK, (
            f"Expected status code 200, but got {response.status_code}"
        )
        assert 'channels' in response.data, "Response is missing 'channels' key"
        assert 'messages' in response.data, "Response is missing 'messages' key"

        channels = response.data['channels']
        messages = response.data['messages']

        assert len(channels) > 0, "No channels were returned"
        assert len(messages) > 0, "No messages were returned"

        channel = channels[0]
        assert 'channel_id' in channel, "Channel is missing 'channel_id'"
        assert 'channel_source' in channel, "Channel is missing 'channel_source'"
        assert 'key_url' in channel, "Channel is missing 'key_url'"

        message = messages[0]
        assert 'message_id' in message, "Message is missing 'message_id'"
        assert 'channel_id' in message, "Message is missing 'channel_id'"
        assert 'timestamp' in message, "Message is missing 'timestamp'"

    def test_retrieve_messages_no_auth(self, client):
        response = client.get(self.url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED, (
            f"Expected status code 401 for unauthorized access, but got {response.status_code}"
        )

    def test_retrieve_messages_no_data(self, client):
        Channel.objects.all().delete()
        Message.objects.all().delete()

        response = client.get(self.url)

        assert response.status_code == status.HTTP_200_OK, (
            f"Expected status code 200, but got {response.status_code}"
        )
        assert 'channels' in response.data, "Response is missing 'channels' key"
        assert 'messages' in response.data, "Response is missing 'messages' key"
        assert len(response.data['channels']) == 0, "Expected empty channels list"
        assert len(response.data['messages']) == 0, "Expected empty messages list"

    def test_retrieve_messages_multiple_channels(self, authed_client, fcm_device):
        channels = ChannelFactory.create_batch(5, connect_user=fcm_device.user)
        for channel in channels:
            Message.objects.create_batch(5, channel=channel, content=b"Test message 2")

        response = authed_client.get(self.url)

        assert response.status_code == status.HTTP_200_OK, (
            f"Expected status code 200, but got {response.status_code}"
        )
        assert len(response.data['channels']) == 5, "Expected 5 channels"
        assert len(response.data['messages']) == 25, "Expected 25 messages"


@pytest.mark.django_db
class TestUpdateConsentView:

    def test_consent(self, authed_client, channel, consent=False):
        url = reverse('connectmessaging:update_consent')
        data = {'channel': str(channel.channel_id), 'consent': consent}
        response = authed_client.post(url, data, content_type='application/json')
        assert response.status_code == status.HTTP_200_OK, (
            f"Expected status code 200, but got {response.status_code}"
        )
        channel.refresh_from_db()
        assert channel.user_consent == consent, (
            f"Expected user_consent to be {consent}, but got {channel.user_consent}"
        )

    def test_restrict_consent(self, authed_client, channel):
        channel.user_consent = False
        channel.save()
        channel.refresh_from_db()
        self.test_consent(authed_client, channel, True)

    def test_invalid_channel_id(self, authed_client):
        url = reverse('connectmessaging:update_consent')
        data = {'channel': str(uuid4()), 'consent': False}
        response = authed_client.post(url, data, content_type='application/json')
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestUpdateReceivedView:
    url = reverse('connectmessaging:update_received')

    def test_update_received(self, authed_client, channel):
        MessageFactory.create_batch(5, channel=channel)
        messages = Message.objects.all()
        message_ids = [message.message_id for message in messages]
        data = {'messages': message_ids}
        response = authed_client.post(self.url, data, content_type=APPLICATION_JSON)

        assert response.status_code == status.HTTP_200_OK

        for message in messages:
            message.refresh_from_db()
            assert message.received is not None, (
                f"Message with ID {message.message_id} should have been updated"
            )

    def test_empty_message_list(self, authed_client):
        data = {'messages': []}
        response = authed_client.post(self.url, data, content_type=APPLICATION_JSON)

        assert response.status_code == status.HTTP_200_OK
        assert Message.objects.filter(received__isnull=False).count() == 0

    def test_invalid_message_ids(self, authed_client):
        invalid_message_ids = [str(uuid4()), str(uuid4())]  # Using valid UUIDs for testing
        data = {'messages': invalid_message_ids}
        response = authed_client.post(self.url, data, content_type='application/json')

        assert response.status_code == status.HTTP_200_OK
        assert Message.objects.filter(received__isnull=True).count() == Message.objects.count()

