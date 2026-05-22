import csv
from datetime import datetime
from unittest import mock

import pytest
from django.utils.timezone import make_aware

from users.factories import UserFactory
from users.models import ConnectUser
from users.tasks import CONNECT_USER_DUMP_FIELDS, BigQueryUploader, CSVGenerator, SupersetUploader


@pytest.fixture
def superset_config():
    return {
        "base_url": "https://superset.example.com",
        "username": "superset",
        "password": "secret",
        "database_id": 5,
        "table_name": "connect_user_dump",
        "table_schema": "public",
    }


@pytest.mark.django_db
def test_csv_generator_outputs_expected_rows():
    user_data = {
        "username": "alice",
        "name": "Alice Smith",
        "phone_number": "+12025550123",
        "phone_validated": True,
        "recovery_phone": "+12025550000",
        "recovery_phone_validated": True,
        "date_joined": make_aware(datetime(2023, 1, 1, 8, 30, 0)),
        "last_login": make_aware(datetime(2023, 1, 3, 9, 15, 0)),
        "device_security": "pin",
        "is_locked": True,
        "is_active": True,
        "failed_backup_code_attempts": 2,
        "hq_sso_date": make_aware(datetime(2023, 1, 2, 12, 0, 0)),
    }
    user = UserFactory(**user_data)

    with CSVGenerator(ConnectUser.objects.all(), CONNECT_USER_DUMP_FIELDS) as csv_path:
        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))

    assert len(rows) == 1
    row = rows[0]
    expected_row = {field: str(CSVGenerator._serialize(getattr(user, field))) for field in CONNECT_USER_DUMP_FIELDS}
    for field in CONNECT_USER_DUMP_FIELDS:
        assert row[field] == expected_row[field]
    assert list(row.keys()) == CONNECT_USER_DUMP_FIELDS


@pytest.mark.django_db
def test_csv_generator_raises_when_max_rows_exceeded():
    UserFactory.create_batch(3)
    with pytest.raises(ValueError, match="exceeds limit"):
        with CSVGenerator(ConnectUser.objects.all(), CONNECT_USER_DUMP_FIELDS, max_rows=2):
            pass


def test_superset_uploader_posts_csv(tmp_path, settings, superset_config):
    settings.SUPERSET_UPLOAD_CONFIG = superset_config
    uploader = SupersetUploader("connect_user_dump")
    csv_path = tmp_path / "dump.csv"
    csv_path.write_text("content")

    with mock.patch.object(uploader, "_authenticate"), mock.patch.object(
        uploader, "_request", return_value={}
    ) as mock_request:
        uploader.upload(csv_path)

    assert mock_request.call_count == 1
    method, path = mock_request.call_args[0]
    kwargs = mock_request.call_args.kwargs
    assert method == "post"
    assert path == f"/api/v1/database/{superset_config['database_id']}/upload/"
    assert kwargs["data"]["table_name"] == "connect_user_dump"
    assert kwargs["data"]["schema"] == superset_config["table_schema"]
    assert kwargs["data"]["already_exists"] == "replace"
    assert kwargs["files"]["file"][0] == csv_path.name


def test_superset_authenticate_sets_session_headers(settings, superset_config):
    settings.SUPERSET_UPLOAD_CONFIG = superset_config
    uploader = SupersetUploader("connect_user_dump")

    with mock.patch.object(uploader, "_request", side_effect=[{"access_token": "token"}, {"result": "csrf-token"}]):
        uploader._authenticate()

    assert uploader.session.headers["Authorization"] == "Bearer token"
    assert uploader.session.headers["X-CSRFToken"] == "csrf-token"
    assert uploader.session.headers["Referer"] == f"{superset_config['base_url']}/"


def test_bigquery_uploader_loads_csv(tmp_path, settings):
    settings.BIGQUERY_DATASET_ID = "my_dataset"
    settings.GOOGLE_APPLICATION_CREDENTIALS = {"project_id": "my_project", "type": "service_account"}
    uploader = BigQueryUploader("configuration_session_dump")
    csv_path = tmp_path / "dump.csv"
    csv_path.write_text("key,created\nabc,2024-01-01")

    mock_job = mock.Mock()
    mock_client = mock.Mock()
    mock_client.load_table_from_file.return_value = mock_job

    with mock.patch("users.tasks.service_account.Credentials.from_service_account_info"), mock.patch(
        "users.tasks.bigquery.Client", return_value=mock_client
    ):
        uploader.upload(csv_path)

    mock_client.load_table_from_file.assert_called_once()
    call_kwargs = mock_client.load_table_from_file.call_args
    assert call_kwargs[0][1] == "my_project.my_dataset.configuration_session_dump"
    mock_job.result.assert_called_once()
