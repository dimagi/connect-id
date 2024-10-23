import base64
import json
from collections import defaultdict
from unittest import mock
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from django.urls import reverse
from firebase_admin import messaging
from oauth2_provider.models import Application
from rest_framework import status

from messaging.factories import ChannelFactory, MessageFactory, ServerFactory
from messaging.models import Channel, Message, MessageStatus
from messaging.serializers import MessageData
from users.factories import FCMDeviceFactory

APPLICATION_JSON = "application/json"


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
def server(oauth_app):
    return ServerFactory(oauth_application=oauth_app)


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
    return messaging.BatchResponse(
        [
            messaging.SendResponse({"name": f"message_id_{i}"}, None)
            for i, message in enumerate(messages)
        ]
    )


@pytest.fixture
def channel(user, server, consent=True):
    return ChannelFactory(connect_user=user, user_consent=consent, server=server)


def rest_channel_data(user=None, consent=False):
    return {
        "user_consent": consent,
        "connectid": str(user.id) if user else None,
        "channel_source": "hq project space",
    }


def rest_message(channel_id=None):
    content = base64.b64encode(b"Hello, World!").decode("utf-8")
    return {"channel": str(channel_id) if channel_id else None, "content": content}


@pytest.mark.django_db
class TestCreateChannelView:
    @staticmethod
    def post_channel_request(client, data, expected_status, expected_error_field=None):
        url = reverse("messaging:create_channel")
        response = client.post(url, data=data, content_type=APPLICATION_JSON)

        assert (
                response.status_code == expected_status
        ), f"Expected status {expected_status}, but got {response.status_code} - {response.content}"

        if expected_status == status.HTTP_400_BAD_REQUEST and expected_error_field:
            json_data = response.json()
            assert (
                    expected_error_field in json_data
            ), f"'{expected_error_field}' field should be in response errors: {json_data}"

        return response

    def test_create_channel_success(self, authed_client, fcm_device, oauth_app):
        server = ServerFactory.create(oauth_application=oauth_app)
        data = rest_channel_data(fcm_device.user)

        with mock.patch(
                "fcm_django.models.messaging.send_all", wraps=_fake_send
        ) as mock_send_message:
            response = self.post_channel_request(
                authed_client, data, status.HTTP_201_CREATED
            )

            json_data = response.json()
            assert (
                    "channel_id" in json_data
            ), f"'channel_id' not found in response data: {json_data}"
            channel_id = json_data["channel_id"]

            mock_send_message.assert_called_once()
            messages = mock_send_message.call_args.args[0]

            assert len(messages) == 1
            message = messages[0]
            assert message.token == fcm_device.registration_id
            assert message.notification.title == "Channel created"
            assert (
                    message.notification.body
                    == "Please provide your consent to send/receive message."
            )
            assert message.data == {"keyUrl": server.key_url}


@pytest.mark.django_db
def test_send_fcm_notification_view(authed_client, channel):
    url = reverse("messaging:send_fcm")
    data = rest_message(channel.channel_id)

    with mock.patch(
            "messaging.views.send_bulk_message"
    ) as mock_send_bulk_message:
        response = authed_client.post(url, data)
        json_data = response.json()
        assert (
                response.status_code == status.HTTP_200_OK
        ), f"Expected status {status.HTTP_200_OK}, but got {response.status_code}."
        assert (
                "message_id" in json_data
        ), "Expected 'message_id' in response data, but it was missing."

        message_id = json_data["message_id"]
        db_msg = Message.objects.get(message_id=message_id)
        assert db_msg

        message_to_send = MessageData(
            usernames=[channel.connect_user.username],
            data={
                "message_id": db_msg.message_id,
                "channel_id": str(channel.channel_id),
                "content": db_msg.content,
            },
        )

        mock_send_bulk_message.assert_called_once_with(message_to_send)


@pytest.mark.django_db
class TestSendMessageView:
    url = reverse("messaging:post_message")

    def test_send_message_from_mobile(self, auth_device, channel, server):
        data = rest_message(channel.channel_id)

        with patch(
                "messaging.views.send_messages_to_service_and_mark_status"
        ) as mock_make_request:
            response = auth_device.post(self.url, data)
            json_data = response.json()
            assert response.status_code == status.HTTP_201_CREATED
            assert "message_id" in json_data

            message_id = json_data["message_id"][0]
            assert Message.objects.filter(message_id=message_id).exists()

            msg = Message.objects.filter(message_id=message_id).first()

            # Prepare the expected message data in a defaultdict format
            expected_message_data = defaultdict(lambda: {"messages": [], "url": None})
            expected_message_data[str(channel.channel_id)] = {
                "url": server.delivery_url,
                "messages": [msg]
            }

            mock_make_request.assert_called_once_with(
                expected_message_data,
                MessageStatus.SENT_TO_SERVICE
            )

    def test_multiple_messages(self, auth_device, channel, server):
        data = [rest_message(channel.channel_id), rest_message(channel.channel_id)]

        with mock.patch(
                "messaging.views.send_messages_to_service_and_mark_status"
        ) as mock_send_bulk_message:
            response = auth_device.post(
                self.url,
                data=json.dumps(data),
                content_type="application/json",
            )
            json_data = response.json()

            assert (
                    response.status_code == status.HTTP_201_CREATED
            ), f"Expected status {status.HTTP_201_CREATED}, but got {response.status_code}."
            assert (
                    "message_id" in json_data
            ), "Expected 'message_id' in response data, but it was missing."

            message_ids = json_data["message_id"]
            assert (
                    len(message_ids) == 2
            ), f"Expected 2 message IDs, but got {len(message_ids)}"

            assert mock_send_bulk_message.call_count == 1

            expected_message_data = defaultdict(lambda: {"messages": [], "url": None})
            expected_messages = [Message.objects.get(message_id=msg_id) for msg_id in message_ids]
            expected_message_data[str(channel.channel_id)] = {
                "url": server.delivery_url,
                "messages": expected_messages
            }

            mock_send_bulk_message.assert_called_once_with(
                expected_message_data,
                MessageStatus.SENT_TO_SERVICE
            )


@pytest.mark.django_db
class TestRetrieveMessagesView:
    url = reverse("messaging:retrieve_messages")

    def test_retrieve_messages_success(self, auth_device, fcm_device):
        ch = ChannelFactory.create(connect_user=fcm_device.user, server=ServerFactory.create())
        MessageFactory.create_batch(10, channel=ch)

        response = auth_device.get(self.url)
        json_data = response.json()

        assert (
                response.status_code == status.HTTP_200_OK
        ), f"Expected status code 200, but got {response.status_code}"
        assert "channels" in json_data, "Response is missing 'channels' key"
        assert "messages" in json_data, "Response is missing 'messages' key"

        channels = json_data["channels"]
        messages = json_data["messages"]

        assert len(channels) > 0, "No channels were returned"
        assert len(messages) > 0, "No messages were returned"

        channel = channels[0]
        assert "channel_id" in channel, "Channel is missing 'channel_id'"
        assert "channel_source" in channel, "Channel is missing 'channel_source'"
        assert "key_url" in channel, "Channel is missing 'key_url'"

        message = messages[0]
        assert "message_id" in message, "Message is missing 'message_id'"
        assert "channel" in message, "Message is missing 'channel_id'"
        assert "timestamp" in message, "Message is missing 'timestamp'"

    def test_retrieve_messages_no_data(self, auth_device):
        Channel.objects.all().delete()
        Message.objects.all().delete()

        response = auth_device.get(self.url)
        json_data = response.json()

        assert (
                response.status_code == status.HTTP_200_OK
        ), f"Expected status code 200, but got {response.status_code}"
        assert "channels" in json_data, "Response is missing 'channels' key"
        assert "messages" in json_data, "Response is missing 'messages' key"
        assert len(json_data["channels"]) == 0, "Expected empty channels list"
        assert len(json_data["messages"]) == 0, "Expected empty messages list"

    def test_retrieve_messages_multiple_channels(self, auth_device, fcm_device):
        channels = ChannelFactory.create_batch(5, connect_user=fcm_device.user, server=ServerFactory.create())
        for channel in channels:
            MessageFactory.create_batch(5, channel=channel, content=b"Test message 2")

        response = auth_device.get(self.url)
        json_data = response.json()
        assert (
                response.status_code == status.HTTP_200_OK
        ), f"Expected status code 200, but got {response.status_code}"
        assert len(json_data["channels"]) == 5, "Expected 5 channels"
        assert len(json_data["messages"]) == 25, "Expected 25 messages"


@pytest.mark.django_db
class TestUpdateConsentView:
    url = reverse("messaging:update_consent")

    def test_consent(self, auth_device, channel, server, consent=False, ):
        with patch(
                "messaging.views.make_request"
        ) as mock_make_request:
            mock_make_request.return_value = Mock(status_code=status.HTTP_200_OK)
            data = {
                "channel": str(channel.channel_id),
                "consent": consent,
            }
            json_data = json.dumps(data)
            response = auth_device.post(
                self.url, json_data, content_type="application/json"
            )

            assert (
                    response.status_code == status.HTTP_200_OK
            ), f"Expected status code 200, but got {response.status_code}"
            channel.refresh_from_db()

            assert (
                    channel.user_consent == consent
            ), f"Expected user_consent to be {consent}, but got {channel.user_consent}"

            mock_make_request.assert_called_once_with(
                url=server.consent_url,
                json_data={
                    "channel_id": str(channel.channel_id),
                    "consent": str(consent),
                },
                secret= server.oauth_application.client_secret
            )

    def test_restrict_consent(self, auth_device, channel, server):
        channel.user_consent = False
        channel.save()
        channel.refresh_from_db()
        self.test_consent(auth_device, channel, server, True)

    def test_invalid_channel_id(self, auth_device):
        url = reverse("messaging:update_consent")
        data = {"channel": str(uuid4()), "consent": False}
        data = json.dumps(data)
        response = auth_device.post(url, data, content_type="application/json")
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestUpdateReceivedView:
    url = reverse("messaging:update_received")

    def test_update_received(self, auth_device, channel):
        messages = MessageFactory.create_batch(5, channel=channel)
        message_ids = [str(message.message_id) for message in messages]

        data = {"messages": message_ids}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type="application/json")

        assert response.status_code == status.HTTP_200_OK

        for message in messages:
            message.refresh_from_db()
            assert (
                    message.received is not None
            ), f"Message {message.message_id} should have a 'received' timestamp"

    def test_empty_message_list(self, auth_device):
        data = {"messages": []}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type="application/json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert Message.objects.filter(received__isnull=False).count() == 0

    def test_invalid_message_ids(self, auth_device):
        invalid_message_ids = [str(uuid4()), str(uuid4())]
        data = {"messages": invalid_message_ids}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type="application/json")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert Message.objects.filter(received__isnull=False).count() == 0

    @patch("messaging.views.send_messages_to_service_and_mark_status")
    def test_grouped_channel_messages(self, mock_send_messages, auth_device):
        channel1 = ChannelFactory.create(server=ServerFactory.create())
        channel2 = ChannelFactory.create(server=ServerFactory.create())
        messages1 = MessageFactory.create_batch(3, channel=channel1)
        messages2 = MessageFactory.create_batch(2, channel=channel2)

        message_ids = [str(message.message_id) for message in messages1 + messages2]

        data = {"messages": message_ids}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type="application/json")

        assert response.status_code == status.HTTP_200_OK

        for message in messages1:
            message.refresh_from_db()
            assert message.received is not None
            assert message.status == MessageStatus.DELIVERED

        for message in messages2:
            message.refresh_from_db()
            assert message.received is not None
            assert message.status == MessageStatus.DELIVERED

        # Validate the mock call
        mock_send_messages.assert_called_once()
        args, kwargs = mock_send_messages.call_args
        assert len(args) == 2
        assert isinstance(args[0], defaultdict)
        assert len(args[0]) == 2
        assert str(channel1.channel_id) in args[0]
        assert str(channel2.channel_id) in args[0]
        assert all(
            msg["received"] is not None
            for msg in args[0][str(channel1.channel_id)]["messages"]
        )
        assert all(
            msg["received"] is not None
            for msg in args[0][str(channel2.channel_id)]["messages"]
        )
        assert isinstance(args[1], MessageStatus)
        assert args[1] == MessageStatus.CONFIRMED_RECEIVED

