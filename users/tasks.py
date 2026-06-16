import csv
import logging
import tempfile
from datetime import date, datetime
from pathlib import Path

import requests
from celery import shared_task
from django.conf import settings
from google.auth.exceptions import GoogleAuthError
from google.cloud import bigquery
from google.oauth2 import service_account
from phonenumber_field.phonenumber import PhoneNumber

from users.models import ConfigurationSession, ConnectUser

logger = logging.getLogger(__name__)

CONNECT_USER_DUMP_FIELDS = [
    "username",
    "name",
    "phone_number",
    "phone_validated",
    "recovery_phone",
    "recovery_phone_validated",
    "date_joined",
    "last_login",
    "device_security",
    "is_locked",
    "is_active",
    "failed_backup_code_attempts",
    "hq_sso_date",
]

CONFIGURATION_SESSION_DUMP_FIELDS = [
    "key",
    "created",
    "expires",
    "phone_number",
    "is_phone_validated",
    "gps_location",
    "invited_user",
    "device_id",
    "device",
]


class SupersetUploadException(Exception):
    pass


class CSVGenerator:
    def __init__(self, queryset, fields, max_rows=None):
        self.queryset = queryset
        self.fields = fields
        self.max_rows = max_rows
        self._path = None

    def __enter__(self) -> Path:
        if self.max_rows and self.queryset.count() > self.max_rows:
            raise ValueError(f"Row count exceeds limit of {self.max_rows}")
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(mode="w", newline="", suffix=".csv", delete=False)
            writer = csv.DictWriter(tmp, fieldnames=self.fields)
            writer.writeheader()
            for row in self.queryset.values(*self.fields).iterator(chunk_size=500):
                writer.writerow({k: self._serialize(row[k]) for k in self.fields})
        except Exception:
            if tmp is not None:
                tmp.close()
                Path(tmp.name).unlink(missing_ok=True)
            raise
        tmp.close()
        self._path = Path(tmp.name)
        return self._path

    def __exit__(self, *args):
        if self._path:
            try:
                self._path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning("Failed to delete temporary file %s", self._path, exc_info=True)

    @staticmethod
    def _serialize(value):
        if value is None:
            return ""
        if isinstance(value, PhoneNumber):
            return value.as_e164
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        return value


class SupersetUploader:
    def __init__(self, table_name):
        self.session = requests.Session()
        config = getattr(settings, "SUPERSET_UPLOAD_CONFIG", {})
        self.base_url = config.get("base_url") or ""
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.database_id = config.get("database_id")
        self.schema = config.get("table_schema", "")
        self.table_name = table_name

    def upload(self, csv_path: Path) -> bool:
        if not (self.base_url and self.username and self.password):
            return False
        self._authenticate()
        payload = {"type": "csv", "table_name": self.table_name, "already_exists": "replace"}
        if self.schema:
            payload["schema"] = self.schema
        with csv_path.open("rb") as f:
            self._request(
                "post",
                f"/api/v1/database/{self.database_id}/upload/",
                data=payload,
                files={"file": (csv_path.name, f, "text/csv")},
            )
        return True

    def _authenticate(self):
        data = self._request(
            "post",
            "/api/v1/security/login",
            json={"username": self.username, "password": self.password, "provider": "db", "refresh": True},
        )
        token = data.get("access_token")
        if not token:
            raise SupersetUploadException("Superset login failed: missing access_token")
        self.session.headers.update({"Authorization": f"Bearer {token}"})

        data = self._request("get", "/api/v1/security/csrf_token/")
        csrf = data.get("result")
        if not csrf:
            raise SupersetUploadException("Superset CSRF token missing")
        self.session.headers.update({"X-CSRFToken": csrf, "Referer": f"{self.base_url}/"})

    def _request(self, method, path, **kwargs):
        response = self.session.request(method, f"{self.base_url}{path}", timeout=60, **kwargs)
        response.raise_for_status()
        return response.json()


CONFIGURATION_SESSION_BQ_SCHEMA = [
    bigquery.SchemaField("key", "STRING"),
    bigquery.SchemaField("created", "TIMESTAMP"),
    bigquery.SchemaField("expires", "TIMESTAMP"),
    bigquery.SchemaField("phone_number", "STRING"),
    bigquery.SchemaField("is_phone_validated", "BOOL"),
    bigquery.SchemaField("gps_location", "STRING"),
    bigquery.SchemaField("invited_user", "BOOL"),
    bigquery.SchemaField("device_id", "STRING"),
    bigquery.SchemaField("device", "STRING"),
]


class BigQueryUploader:
    def __init__(self, table_name, schema=None):
        self.dataset_id = settings.BIGQUERY_DATASET_ID
        self.table_name = table_name
        self.schema = schema

    def upload(self, csv_path: Path) -> bool:
        if not self.dataset_id:
            return False
        try:
            credentials = service_account.Credentials.from_service_account_info(
                settings.BIGQUERY_GOOGLE_APPLICATION_CREDENTIALS
            )
        except GoogleAuthError:
            logger.error("Error in Google credentials configuration", exc_info=True)
            return False
        project_id = settings.BIGQUERY_GOOGLE_APPLICATION_CREDENTIALS["project_id"]
        client = bigquery.Client(project=project_id, credentials=credentials)
        table_ref = f"{project_id}.{self.dataset_id}.{self.table_name}"
        job_config = bigquery.LoadJobConfig(
            autodetect=self.schema is None,
            schema=self.schema,
            write_disposition="WRITE_TRUNCATE",
            source_format=bigquery.SourceFormat.CSV,
            skip_leading_rows=1,
        )
        with csv_path.open("rb") as f:
            job = client.load_table_from_file(f, table_ref, job_config=job_config)
        job.result()
        return True


@shared_task(name="users.tasks.upload_configuration_sessions")
def upload_configuration_sessions():
    table_name = settings.BIGQUERY_CONFIGURATION_SESSION_TABLE
    with CSVGenerator(
        ConfigurationSession.objects.all(), CONFIGURATION_SESSION_DUMP_FIELDS, max_rows=500000
    ) as csv_path:
        bq_uploaded = BigQueryUploader(table_name, schema=CONFIGURATION_SESSION_BQ_SCHEMA).upload(csv_path)
        superset_uploaded = SupersetUploader(table_name).upload(csv_path)
    logger.info("ConfigurationSession upload finished (bigquery=%s, superset=%s)", bq_uploaded, superset_uploaded)


@shared_task(name="users.tasks.upload_connect_users_to_superset")
def upload_connect_users_to_superset():
    table_name = settings.SUPERSET_UPLOAD_CONFIG["table_name"]
    with CSVGenerator(ConnectUser.objects.all(), CONNECT_USER_DUMP_FIELDS, max_rows=100000) as csv_path:
        uploaded = SupersetUploader(table_name).upload(csv_path)
    logger.info("ConnectUser upload to Superset finished (uploaded=%s)", uploaded)
