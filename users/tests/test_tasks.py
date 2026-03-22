import csv
from datetime import datetime
from unittest import mock

import pytest
from django.utils.timezone import make_aware

from users.factories import UserFactory
from users.tasks import CONNECT_USER_DUMP_FIELDS, ConnectUserSupersetExporter


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
def test_write_csv_outputs_expected_rows(settings, superset_config):
    settings.SUPERSET_UPLOAD_CONFIG = superset_config
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

    exporter = ConnectUserSupersetExporter()
    csv_path = exporter.generate_csv()
    try:
        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
    finally:
        csv_path.unlink(missing_ok=True)

    assert len(rows) == 1
    row = rows[0]
    expected_row = {
        field: str(ConnectUserSupersetExporter._serialize_value(getattr(user, field)))
        for field in CONNECT_USER_DUMP_FIELDS
    }
    for field in CONNECT_USER_DUMP_FIELDS:
        assert row[field] == expected_row[field]
    assert list(row.keys()) == CONNECT_USER_DUMP_FIELDS


def test_upload_posts_csv_to_superset(tmp_path, settings, superset_config):
    settings.SUPERSET_UPLOAD_CONFIG = superset_config
    exporter = ConnectUserSupersetExporter()
    csv_path = tmp_path / "dump.csv"
    csv_path.write_text("content")

    with mock.patch.object(exporter, "_request", return_value=mock.Mock()) as mock_request:
        exporter.upload(csv_path)

    assert mock_request.call_count == 1
    method, path = mock_request.call_args[0]
    kwargs = mock_request.call_args.kwargs
    assert method == "post"
    assert path == f"/api/v1/database/{superset_config['database_id']}/csv_upload/"
    assert kwargs["data"]["table_name"] == superset_config["table_name"]
    assert kwargs["data"]["schema"] == superset_config["table_schema"]
    assert kwargs["data"]["already_exists"] == "replace"
    uploaded_file = kwargs["files"]["file"]
    assert uploaded_file[0] == csv_path.name


def test_authenticate_sets_session_headers(settings, superset_config):
    settings.SUPERSET_UPLOAD_CONFIG = superset_config
    exporter = ConnectUserSupersetExporter()

    with mock.patch.object(exporter, "_login", return_value="token") as mock_login, mock.patch.object(
        exporter, "_get_csrf_token", return_value="csrf-token"
    ) as mock_csrf:
        exporter.authenticate()

    mock_login.assert_called_once()
    mock_csrf.assert_called_once()
    assert exporter.session.headers["Authorization"] == "Bearer token"
    assert exporter.session.headers["X-CSRFToken"] == "csrf-token"
    assert exporter.session.headers["Referer"] == f"{superset_config['base_url']}/"
