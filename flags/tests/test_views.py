import json

import pytest
from django.urls import reverse

from ..factories import SwitchFactory


@pytest.mark.django_db
class TestTogglesView:
    endpoint = reverse("toggles")

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
