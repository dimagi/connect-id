import base64
import json
from unittest import mock
from unittest.mock import call
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.urls import reverse
from oauth2_provider.models import Application
from rest_framework import status

from connectmessaging.factories import ChannelFactory, MessageFactory
from connectmessaging.models import Message, Channel
from messaging.serializers import Message as Msg
from messaging.tests import _fake_send

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
def authed_client(client, oauth_app):
    auth = f"{oauth_app.client_id}:{oauth_app.raw_client_secret}".encode("utf-8")
    credentials = base64.b64encode(auth).decode("utf-8")
    client.defaults["HTTP_AUTHORIZATION"] = "Basic " + credentials
    return client


@pytest.fixture
def channel(user, consent=True):
    return ChannelFactory(connect_user=user, user_consent=consent)


def rest_channel_data(user=None, consent=False):
    return {
        "user_consent": consent,
        "connect_user": str(user.id) if user else None,
        "channel_source": "hq project space",
        "key_url": "https://example.com/key",
        "callback_url": "https://example.com/callback",
        "delivery_url": "https://example.com/delivery",
    }


def rest_message(channel_id=None):
    content = base64.b64encode(b"Hello, World!").decode('utf-8')
    return {"channel": str(channel_id) if channel_id else None, "content": content}


@pytest.mark.django_db
class TestCreateChannelView:
    @staticmethod
    def post_channel_request(client, data, expected_status, expected_error_field=None):
        """
        Helper method to send a POST request to create a channel and check the response.
        """
        url = reverse("connectmessaging:create_channel")
        response = client.post(url, data=data, content_type=APPLICATION_JSON)

        assert (
                response.status_code == expected_status
        ), f"Expected status {expected_status}, but got {response.status_code} - {response.data}"

        if expected_status == status.HTTP_400_BAD_REQUEST and expected_error_field:
            assert (
                    expected_error_field in response.data
            ), f"'{expected_error_field}' field should be in response errors: {response.data}"

        return response

    def test_create_channel_success(self, authed_client, fcm_device):
        data = rest_channel_data(fcm_device.user)

        with mock.patch(
                "fcm_django.models.messaging.send_all", wraps=_fake_send
        ) as mock_send_message:
            response = self.post_channel_request(
                authed_client, data, status.HTTP_201_CREATED
            )

            assert (
                    "channel_id" in response.data
            ), f"'channel_id' not found in response data: {response.data}"
            channel_id = response.data["channel_id"]

            mock_send_message.assert_called_once()
            messages = mock_send_message.call_args.args[0]

            assert len(messages) == 1
            message = messages[0]
            assert message.token == fcm_device.registration_id
            assert message.notification.title == "Channel created"
            assert (
                    message.notification.body
                    == "A new channel has been created for you. Please provide your consent to proceed."
            )
            assert message.data == {"keyUrl": data["key_url"]}

    def test_missing_keys(self, authed_client, fcm_device):
        required_keys = [
            "connect_user",
            "key_url",
            "callback_url",
            "channel_source",
            "delivery_url",
        ]
        for key in required_keys:
            data = rest_channel_data(fcm_device.user)
            data.pop(key)
            self.post_channel_request(
                authed_client, data, status.HTTP_400_BAD_REQUEST, key
            )


@pytest.mark.django_db
class TestSendMessageView:
    url = reverse("connectmessaging:send_message")

    def test_send_message_from_mobile_with_no_user_consent(self, auth_device, channel):
        data = rest_message(channel.channel_id)
        channel.user_consent = False
        channel.save()
        channel.refresh_from_db()

        with patch(
                "connectmessaging.views.make_request_to_service"
        ) as mock_make_request:
            response = auth_device.post(self.url, data)

            assert (
                    response.status_code == status.HTTP_403_FORBIDDEN
            ), f"Expected status {status.HTTP_403_FORBIDDEN}, but got {response.status_code}."

            mock_make_request.assert_not_called()

    def test_send_message_from_mobile(self, auth_device, channel):
        data = rest_message(channel.channel_id)

        with patch(
                "connectmessaging.views.make_request_to_service"
        ) as mock_make_request:
            response = auth_device.post(self.url, data)

            assert (
                    response.status_code == status.HTTP_201_CREATED
            ), f"Expected status {status.HTTP_201_CREATED}, but got {response.status_code}."
            assert (
                    "message_id" in response.data
            ), "Expected 'message_id' in response data, but it was missing."

            message_id = response.data["message_id"][0]
            assert Message.objects.filter(message_id=message_id).exists()

            mock_make_request.assert_called_once_with(
                channel.delivery_url,
                json_data=Message.objects.get(message_id=message_id),
            )

    def test_send_message_from_hq(self, authed_client, channel):
        channel.delivery_url = "www.commcarehq.org/a/domain/connect_incoming"
        channel.save()
        channel.refresh_from_db()
        data = rest_message(channel.channel_id)
        headers = {"HTTP_HOST": "commcarehq.org"}

        with mock.patch(
                "connectmessaging.views.send_bulk_message"
        ) as mock_send_bulk_message:
            response = authed_client.post(self.url, data, **headers)

            assert (
                    response.status_code == status.HTTP_201_CREATED
            ), f"Expected status {status.HTTP_201_CREATED}, but got {response.status_code}."
            assert (
                    "message_id" in response.data
            ), "Expected 'message_id' in response data, but it was missing."

            message_id = response.data["message_id"][0]
            db_msg = Message.objects.get(message_id=message_id)
            assert db_msg

            message_to_send = Msg(
                usernames=[channel.connect_user.username],
                data={
                    "message_id": db_msg.message_id,
                    "content": db_msg.content,
                },
            )

            mock_send_bulk_message.assert_called_once_with(message_to_send)

    def test_send_message_from_hq_multiples(self, authed_client, channel):
        channel.delivery_url = "www.commcarehq.org/a/domain/connect_incoming"
        channel.save()
        channel.refresh_from_db()

        data = [rest_message(channel.channel_id), rest_message(channel.channel_id)]
        headers = {"HTTP_HOST": "commcarehq.org", "CONTENT_TYPE": "application/json"}

        with mock.patch("connectmessaging.views.send_bulk_message") as mock_send_bulk_message:
            response = authed_client.post(self.url, data=json.dumps(data), content_type="application/json", **headers)

            assert (
                    response.status_code == status.HTTP_201_CREATED
            ), f"Expected status {status.HTTP_201_CREATED}, but got {response.status_code}."
            assert (
                    "message_id" in response.data
            ), "Expected 'message_id' in response data, but it was missing."

            message_ids = response.data["message_id"]
            assert len(message_ids) == 2, f"Expected 2 message IDs, but got {len(message_ids)}"

            assert mock_send_bulk_message.call_count == 2, (f"Expected send_bulk_message to be called 2 "
                                                            f"times, but it was called {mock_send_bulk_message.call_count} times.")

            expected_calls = []
            for message_id in message_ids:
                db_msg = Message.objects.get(message_id=message_id)
                assert db_msg
                expected_calls.append(call(Msg(
                    usernames=[channel.connect_user.username],
                    data={
                        "message_id": db_msg.message_id,
                        "content": db_msg.content,
                    },
                )))

            mock_send_bulk_message.assert_has_calls(expected_calls, any_order=True)


@pytest.mark.django_db
class TestRetrieveMessagesView:
    url = reverse("connectmessaging:retrieve_messages")

    def test_retrieve_messages_success(self, auth_device, fcm_device):
        ch = ChannelFactory.create(connect_user=fcm_device.user)
        MessageFactory.create_batch(10, channel=ch)

        response = auth_device.get(self.url)

        assert (
                response.status_code == status.HTTP_200_OK
        ), f"Expected status code 200, but got {response.status_code}"
        assert "channels" in response.data, "Response is missing 'channels' key"
        assert "messages" in response.data, "Response is missing 'messages' key"

        channels = response.data["channels"]
        messages = response.data["messages"]

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

        assert (
                response.status_code == status.HTTP_200_OK
        ), f"Expected status code 200, but got {response.status_code}"
        assert "channels" in response.data, "Response is missing 'channels' key"
        assert "messages" in response.data, "Response is missing 'messages' key"
        assert len(response.data["channels"]) == 0, "Expected empty channels list"
        assert len(response.data["messages"]) == 0, "Expected empty messages list"

    def test_retrieve_messages_multiple_channels(self, auth_device, fcm_device):
        channels = ChannelFactory.create_batch(5, connect_user=fcm_device.user)
        for channel in channels:
            MessageFactory.create_batch(5, channel=channel, content=b"Test message 2")

        response = auth_device.get(self.url)

        assert (
                response.status_code == status.HTTP_200_OK
        ), f"Expected status code 200, but got {response.status_code}"
        assert len(response.data["channels"]) == 5, "Expected 5 channels"
        assert len(response.data["messages"]) == 25, "Expected 25 messages"


@pytest.mark.django_db
class TestUpdateConsentView:
    url = reverse("connectmessaging:update_consent")

    def test_consent(self, auth_device, channel, consent=False):
        with patch(
                "connectmessaging.views.make_request_to_service"
        ) as mock_make_request:
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
                url="CONSENT_URL",
                json_data={
                    "channel_id": str(channel.channel_id),
                    "consent": str(consent),
                },
            )

    def test_restrict_consent(self, auth_device, channel):
        channel.user_consent = False
        channel.save()
        channel.refresh_from_db()
        self.test_consent(auth_device, channel, True)

    def test_invalid_channel_id(self, auth_device):
        url = reverse("connectmessaging:update_consent")
        data = {"channel": str(uuid4()), "consent": False}
        data = json.dumps(data)
        response = auth_device.post(url, data, content_type="application/json")
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestUpdateReceivedView:
    url = reverse("connectmessaging:update_received")

    def test_update_received(self, auth_device, channel):
        messages = MessageFactory.create_batch(5, channel=channel)
        message_ids = [
            str(message.message_id) for message in messages
        ]

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

        assert response.status_code == status.HTTP_200_OK
        assert Message.objects.filter(received__isnull=False).count() == 0

    def test_invalid_message_ids(self, auth_device):
        invalid_message_ids = [str(uuid4()), str(uuid4())]
        data = {"messages": invalid_message_ids}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type="application/json")

        assert response.status_code == status.HTTP_200_OK
        assert Message.objects.filter(received__isnull=False).count() == 0

    @patch("connectmessaging.views.make_request_to_service")
    def test_grouped_channel_messages(self, mock_make_request, auth_device, channel):
        messages = MessageFactory.create_batch(3, channel=channel)
        messages_random_channel = MessageFactory.create()
        message_ids = [str(message.message_id) for message in messages]
        message_ids.append(str(messages_random_channel.message_id))

        data = {"messages": message_ids}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type="application/json")

        assert response.status_code == status.HTTP_200_OK

        for message in messages:
            message.refresh_from_db()
        messages_random_channel.refresh_from_db()

        # Collect expected calls
        expected_calls = [
            call(
                url=channel.delivery_url,
                json_data={
                    "channel": str(channel.channel_id),
                    "messages": sorted(
                        [
                            {
                                "message_id": str(msg.message_id),
                                "received": str(msg.received),
                            }
                            for msg in messages
                        ],
                        key=lambda x: x["message_id"],
                    ),
                },
            ),
            call(
                url=messages_random_channel.channel.delivery_url,
                json_data={
                    "channel": str(messages_random_channel.channel.channel_id),
                    "messages": [
                        {
                            "message_id": str(messages_random_channel.message_id),
                            "received": str(messages_random_channel.received),
                        }
                    ],
                },
            ),
        ]

        # Collect actual calls made
        actual_calls = mock_make_request.call_args_list

        # Create a helper function to check if two calls match without considering the order of message_ids
        def calls_match(expected, actual):
            expected_json_data = expected.kwargs["json_data"]["messages"]
            actual_json_data = actual.kwargs["json_data"]["messages"]
            return sorted(expected_json_data, key=lambda x: x["message_id"]) == sorted(
                actual_json_data, key=lambda x: x["message_id"]
            )

        # Assert each expected call is found in the actual calls, regardless of order
        for expected in expected_calls:
            assert any(
                calls_match(expected, actual) for actual in actual_calls
            ), f"Expected call {expected} not found in actual calls."
