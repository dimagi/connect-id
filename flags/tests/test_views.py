import json
from unittest import mock

import pytest
from django.urls import reverse

from ..factories import SwitchFactory


@pytest.mark.django_db
class TestTogglesView:
    endpoint = reverse("toggles")

    @pytest.fixture(scope="class", autouse=True)
    def mock_get_user_toggles(self):
        with mock.patch("flags.utils.get_connect_toggles") as mock_connect_toggles:
            mock_connect_toggles.return_value = {}
            yield mock_connect_toggles

    def test_success(self, client):
        SwitchFactory(name="A1")
        SwitchFactory(name="B2", active=False)

        response = client.get(self.endpoint)

        assert response.status_code == 200
        assert response["Content-Type"] == "application/json"

        data = json.loads(response.content)
        assert "toggles" in data
        assert data["toggles"]["A1"] is True
        assert data["toggles"]["B2"] is False

    def test_no_toggles(self, client):
        response = client.get(self.endpoint)

        assert response.status_code == 200
        data = json.loads(response.content)
        assert data == {"toggles": {}}
