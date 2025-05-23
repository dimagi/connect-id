import base64
import json
import uuid
from collections import defaultdict
from unittest import mock
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import pytest
from django.urls import reverse
from firebase_admin import messaging
from rest_framework import status

from messaging.factories import ChannelFactory, MessageFactory, ServerFactory
from messaging.models import Channel, Message, MessageDirection, MessageStatus
from messaging.serializers import MessageSerializer, NotificationData
from users.factories import FCMDeviceFactory

APPLICATION_JSON = "application/json"


@pytest.fixture
def server():
    return ServerFactory()


def test_send_message(authed_client, fcm_device):
    url = reverse("messaging:send_message")

    with mock.patch("fcm_django.models.messaging.send_each", wraps=_fake_send) as mock_send_message:
        response = authed_client.post(
            url,
            data=json.dumps(
                {
                    "username": fcm_device.user.username,
                    "body": "test message",
                    "data": {"test": "data"},
                    "fcm_options": {"analytics_label": "test"},
                }
            ),
            content_type=APPLICATION_JSON,
        )
        assert response.status_code == 200, response.content
        assert response.json() == {
            "all_success": True,
            "responses": [{"username": fcm_device.user.username, "status": "success"}],
        }
        mock_send_message.assert_called_once()
        messages = mock_send_message.call_args_list[0].args[0]
        assert len(messages) == 1
        assert json.loads(str(messages[0])) == {
            "android": {"priority": "high"},
            "fcm_options": {"analytics_label": "test"},
            "data": {"test": "data"},
            "notification": {"body": "test message"},
            "token": fcm_device.registration_id,
        }


def test_send_message_bulk(authed_client, fcm_device):
    url = reverse("messaging:send_message_bulk")

    fcm_device2 = FCMDeviceFactory()
    fcm_device3 = FCMDeviceFactory(active=False)

    with mock.patch("fcm_django.models.messaging.send_each", wraps=_fake_send) as mock_send_message:
        response = authed_client.post(
            url,
            data=json.dumps(
                {
                    "messages": [
                        {
                            "usernames": [
                                fcm_device.user.username,
                                fcm_device.user.username,
                                fcm_device2.user.username,
                            ],
                            "title": "test title1",
                            "body": "test message1",
                            "data": {"test": "data1"},
                        },
                        {
                            "usernames": [fcm_device.user.username, "nonexistent-user", fcm_device3.user.username],
                            "title": "test title2",
                            "body": "test message2",
                            "data": {"test": "data2"},
                        },
                    ]
                }
            ),
            content_type=APPLICATION_JSON,
        )

        assert response.status_code == 200, response.content
        assert mock_send_message.call_count == 2
        messages = mock_send_message.call_args_list[0].args[0]
        assert len(messages) == 2
        assert json.loads(str(messages[0])) == {
            "android": {"priority": "high"},
            "data": {"test": "data1"},
            "notification": {"body": "test message1", "title": "test title1"},
            "token": fcm_device.registration_id,
        }

        assert response.json()["all_success"] is False
        results = response.json()["messages"]
        assert results == [
            {
                "all_success": True,
                "responses": [
                    {"status": "success", "username": fcm_device.user.username},
                    {"status": "success", "username": fcm_device2.user.username},
                ],
            },
            {
                "all_success": False,
                "responses": [
                    {"status": "success", "username": fcm_device.user.username},
                    {"status": "deactivated", "username": "nonexistent-user"},
                    {"status": "deactivated", "username": fcm_device3.user.username},
                ],
            },
        ]


def _fake_send(messages, **kwargs):
    return messaging.BatchResponse(
        [messaging.SendResponse({"name": f"message_id_{i}"}, None) for i, message in enumerate(messages)]
    )


@pytest.fixture
def channel(user, server, consent=True):
    return ChannelFactory(connect_user=user, user_consent=consent, server=server)


def rest_channel_data(user=None, consent=False):
    return {
        "user_consent": consent,
        "connectid": str(user.username) if user else None,
        "channel_source": "hq project space",
    }


def rest_message(channel_id=None):
    content = {"nonce": "test_nonce_value", "tag": "test_tag_value", "ciphertext": "test_ciphertext_value"}
    return {"channel": str(channel_id) if channel_id else None, "content": content, "message_id": str(uuid.uuid4())}


def make_basic_auth_header(server_id: str, secret_key: str) -> str:
    credentials = f"{server_id}:{secret_key}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = f"Basic {encoded_credentials}"
    return {"HTTP_AUTHORIZATION": headers}


@pytest.mark.django_db
class TestCreateChannelView:
    @staticmethod
    def post_channel_request(client, data, expected_status, server, expected_error_field=None):
        url = reverse("messaging:create_channel")
        auth_header = make_basic_auth_header(server.server_id, server.secret_key)
        response = client.post(url, data=json.dumps(data), content_type=APPLICATION_JSON, **auth_header)

        print(response)

        assert response.status_code == expected_status

        if expected_status == status.HTTP_400_BAD_REQUEST and expected_error_field:
            json_data = response.json()
            assert expected_error_field in json_data

        return response

    def test_create_channel_success(self, client, fcm_device, oauth_app, server):
        data = rest_channel_data(fcm_device.user)

        with mock.patch("fcm_django.models.messaging.send_each", wraps=_fake_send) as mock_send_message:
            response = self.post_channel_request(client, data, status.HTTP_201_CREATED, server)

            json_data = response.json()
            assert "channel_id" in json_data

            mock_send_message.assert_called_once()
            messages = mock_send_message.call_args.args[0]

            assert len(messages) == 1
            message = messages[0]
            channel = Channel.objects.get(connect_user__username=data["connectid"])
            assert message.token == fcm_device.registration_id
            assert message.notification.title == "Channel created"
            assert message.notification.body == "Please provide your consent to send/receive message."
            assert message.data == {
                "key_url": server.key_url,
                "action": "ccc_message",
                "channel_source": data["channel_source"],
                "channel_id": str(channel.channel_id),
                "consent": str(channel.user_consent),
            }


@pytest.mark.django_db
def test_send_fcm_notification_view(client, channel):
    url = reverse("messaging:send_fcm")
    data = rest_message(channel.channel_id)
    server = ServerFactory()
    headers = make_basic_auth_header(server.server_id, server.secret_key)

    with mock.patch("messaging.views.send_bulk_notification") as mock_send_bulk_message:
        response = client.post(url, data=data, content_type=APPLICATION_JSON, **headers)
        json_data = response.json()
        assert response.status_code == status.HTTP_200_OK
        assert "message_id" in json_data

        message_id = json_data["message_id"]
        db_msg = Message.objects.get(message_id=message_id)
        assert db_msg

        serialized_msg = MessageSerializer(db_msg).data
        serialized_msg["channel"] = str(db_msg.channel.channel_id)
        expected = NotificationData(
            usernames=[channel.connect_user.username],
            data=serialized_msg,
            title="New Connect Message",
            body=f"You received a new message from {channel.visible_name}",
        )

        mock_send_bulk_message.assert_called_once_with(expected)


@pytest.mark.django_db
class TestSendMessageView:
    url = reverse("messaging:post_message")

    def _get_expected_message_data(self, msgs, channel, server):
        serialized_msgs = []

        # Prepare the expected message data in a defaultdict format
        for m in msgs:
            serialized = MessageSerializer(m).data
            serialized["channel"] = str(serialized["channel"])
            serialized_msgs.append(serialized)
        expected_message_data = defaultdict(lambda: {"messages": [], "url": None})
        expected_message_data[str(channel.channel_id)] = {"url": server.delivery_url, "messages": serialized_msgs}
        return expected_message_data

    def test_send_message_from_mobile(self, auth_device, channel, server):
        data = rest_message(channel.channel_id)

        with patch("messaging.views.send_messages_to_service_and_mark_status") as mock_make_request:
            response = auth_device.post(self.url, json.dumps(data), content_type=APPLICATION_JSON)
            json_data = response.json()
            assert response.status_code == status.HTTP_201_CREATED
            assert "message_id" in json_data

            message_id = json_data["message_id"][0]
            assert Message.objects.filter(message_id=message_id).exists()

            msg = Message.objects.filter(message_id=message_id).first()

            expected_message_data = self._get_expected_message_data([msg], channel, server)
            mock_make_request.assert_called_once_with(expected_message_data, MessageStatus.SENT_TO_SERVICE)

    def test_multiple_messages(self, auth_device, channel, server):
        data = [rest_message(channel.channel_id), rest_message(channel.channel_id)]

        with mock.patch("messaging.views.send_messages_to_service_and_mark_status") as mock_send_bulk_message:
            response = auth_device.post(
                self.url,
                data=json.dumps(data),
                content_type=APPLICATION_JSON,
            )
            json_data = response.json()

            assert response.status_code == status.HTTP_201_CREATED
            assert "message_id" in json_data

            message_ids = json_data["message_id"]
            assert len(message_ids) == 2

            msgs = Message.objects.filter(message_id__in=message_ids)
            expected_message_data = self._get_expected_message_data(msgs, channel, server)
            mock_send_bulk_message.assert_called_once_with(expected_message_data, MessageStatus.SENT_TO_SERVICE)

    def test_message_already_exists(self, auth_device, channel, server):
        data = [rest_message(channel.channel_id), rest_message(channel.channel_id)]
        pending_msg = MessageFactory.create(
            channel=channel, message_id=data[0]["message_id"], status=MessageStatus.PENDING
        )
        MessageFactory.create(
            channel=channel, message_id=UUID(data[1]["message_id"]), status=MessageStatus.SENT_TO_SERVICE
        )

        with mock.patch("messaging.views.send_messages_to_service_and_mark_status") as mock_send_bulk_message:
            response = auth_device.post(
                self.url,
                data=json.dumps(data),
                content_type=APPLICATION_JSON,
            )
            json_data = response.json()
            expected_message_data = self._get_expected_message_data([pending_msg], channel, server)
            mock_send_bulk_message.assert_called_once()
            mock_send_bulk_message.assert_called_once_with(expected_message_data, MessageStatus.SENT_TO_SERVICE)

        assert response.status_code == status.HTTP_201_CREATED
        assert json_data["message_id"] == [pending_msg.message_id]


@pytest.mark.django_db
class TestRetrieveMessagesView:
    url = reverse("messaging:retrieve_messages")

    def test_retrieve_messages_success(self, auth_device, fcm_device):
        print(fcm_device.user.username)
        ch = ChannelFactory.create(connect_user=fcm_device.user, server=ServerFactory.create())
        MessageFactory.create_batch(10, channel=ch, direction=MessageDirection.MOBILE)

        response = auth_device.get(self.url)
        json_data = response.json()

        assert response.status_code == status.HTTP_200_OK
        assert all(key in json_data for key in ["channels", "messages"])
        assert len(json_data["messages"]) == 10

        channel = json_data["channels"][0]
        message = json_data["messages"][0]

        assert all(key in channel for key in ["channel_id", "channel_source", "key_url"])
        assert all(
            key in message for key in ["message_id", "channel", "timestamp", "ciphertext", "tag", "status", "action"]
        )

    def test_retrieve_messages_no_data(self, auth_device):
        Channel.objects.all().delete()
        Message.objects.all().delete()

        response = auth_device.get(self.url)

        response_data = response.json()

        assert response.status_code == status.HTTP_200_OK
        assert all(key in response_data for key in ["channels", "messages"])
        assert all(not response_data[key] for key in ["channels", "messages"])

    def test_retrieve_messages_multiple_channels(self, auth_device, fcm_device):
        channels = ChannelFactory.create_batch(5, connect_user=fcm_device.user, server=ServerFactory.create())
        for channel in channels:
            MessageFactory.create_batch(5, channel=channel, direction=MessageDirection.MOBILE)

        response = auth_device.get(self.url)
        data = response.json()
        assert response.status_code == status.HTTP_200_OK
        assert all(len(data[key]) == expected for key, expected in [("channels", 5), ("messages", 25)])


@pytest.mark.django_db
class TestUpdateConsentView:
    url = reverse("messaging:update_consent")

    def test_consent(
        self,
        auth_device,
        channel,
        server,
        consent=False,
    ):
        with patch("messaging.views.make_request") as mock_make_request:
            mock_make_request.return_value = Mock(status_code=status.HTTP_200_OK)
            data = {
                "channel": str(channel.channel_id),
                "consent": consent,
            }
            json_data = json.dumps(data)
            response = auth_device.post(self.url, json_data, content_type=APPLICATION_JSON)

            assert response.status_code == status.HTTP_200_OK
            channel.refresh_from_db()

            assert channel.user_consent == consent

            mock_make_request.assert_called_once_with(
                url=server.consent_url,
                json_data={
                    "channel_id": str(channel.channel_id),
                    "consent": consent,
                },
                secret=server.secret_key,
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
        response = auth_device.post(url, data, content_type=APPLICATION_JSON)
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestUpdateReceivedView:
    url = reverse("messaging:update_received")

    def test_update_received(self, auth_device, channel):
        messages = MessageFactory.create_batch(5, channel=channel)
        message_ids = [str(message.message_id) for message in messages]

        data = {"messages": message_ids}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type=APPLICATION_JSON)

        assert response.status_code == status.HTTP_200_OK

        for message in messages:
            message.refresh_from_db()
            assert message.received is not None

    def test_empty_message_list(self, auth_device):
        data = {"messages": []}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type=APPLICATION_JSON)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert Message.objects.filter(received__isnull=False).count() == 0

    def test_invalid_message_ids(self, auth_device):
        invalid_message_ids = [str(uuid4()), str(uuid4())]
        data = {"messages": invalid_message_ids}
        data = json.dumps(data)
        response = auth_device.post(self.url, data, content_type=APPLICATION_JSON)

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
        response = auth_device.post(self.url, data, content_type=APPLICATION_JSON)

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
        data, msg_status = args
        assert isinstance(data, defaultdict) and len(data) == 2
        assert all(str(ch.channel_id) in data for ch in [channel1, channel2])
        assert all(
            all(msg["received_on"] for msg in data[str(ch.channel_id)]["messages"]) for ch in [channel1, channel2]
        )
        assert msg_status == MessageStatus.CONFIRMED_RECEIVED
