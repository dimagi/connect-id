import pytest
from django.urls import reverse
from rest_framework import status

from messaging.tests import APPLICATION_JSON
from payments.models import PaymentProfile
from users.factories import UserFactory


@pytest.mark.parametrize(
    "data, expected_status, expected_user1_status, expected_user2_status, result",
    [
        # Scenario 1: Update both statuses successfully
        (
            [
                {"username": "user1", "status": "approved"},
                {"username": "user2", "status": "rejected"},
            ],
            status.HTTP_200_OK,
            "approved",
            "rejected",
            {"approved": 1, "rejected": 1, "pending": 0},
        ),
        # Scenario 2: No change in status
        (
            [
                {"username": "user2", "status": "approved"},
            ],
            status.HTTP_200_OK,
            "pending",  # Should remain unchanged
            "approved",  # Should remain unchanged
            {"approved": 0, "rejected": 0, "pending": 0},
        ),
        # Scenario 3: Invalid user (user doesn't exist)
        (
            [
                {"username": "nonexistent_user", "status": "rejected"},
            ],
            status.HTTP_404_NOT_FOUND,
            "pending",  # No change
            "approved",  # No change
            {},
        ),
        # Scenario 4: Multiple users, one invalid
        (
            [
                {"username": "user1", "status": "approved"},
                {"username": "nonexistent_user", "status": "rejected"},
            ],
            status.HTTP_404_NOT_FOUND,
            "pending",  # No change
            "approved",  # No change
            {},
        ),
    ],
)
def test_validate_phone_numbers(
    authed_client,
    data,
    expected_status,
    expected_user1_status,
    expected_user2_status,
    result,
):
    user1 = UserFactory(username="user1")
    user2 = UserFactory(username="user2")
    PaymentProfile.objects.create(user=user1, phone_number="12345", status="pending")
    PaymentProfile.objects.create(user=user2, phone_number="67890", status="approved")

    url = reverse("validate_payment_phone_numbers")

    response = authed_client.post(url, {"updates": data}, content_type=APPLICATION_JSON)

    assert response.status_code == expected_status

    profile1 = PaymentProfile.objects.get(user=user1)
    profile2 = PaymentProfile.objects.get(user=user2)

    assert profile1.status == expected_user1_status
    assert profile2.status == expected_user2_status
    if response.status_code == 200:
        assert response.json()["result"] == result


def test_fetch_phone_numbers(authed_client):
    user1 = UserFactory(username="user1")
    user2 = UserFactory(username="user2")
    PaymentProfile.objects.create(user=user1, phone_number="12345", status="pending")
    PaymentProfile.objects.create(user=user2, phone_number="67890", status="approved")

    url = reverse("fetch_payment_phone_numbers")

    response = authed_client.get(url, {"usernames": ["user1", "user2"]})
    assert len(response.json()["found_payment_numbers"]) == 2

    response = authed_client.get(url, {"usernames": ["user1", "user2"], "status": "pending"})
    assert len(response.json()["found_payment_numbers"]) == 1

    response = authed_client.get(url, {"usernames": ["user1"], "status": "approved"})
    assert len(response.json()["found_payment_numbers"]) == 0
