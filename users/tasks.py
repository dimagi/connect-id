import csv
import logging
import tempfile
from datetime import date, datetime
from pathlib import Path

import requests
import sentry_sdk
from celery import shared_task
from django.conf import settings
from phonenumber_field.phonenumber import PhoneNumber

from users.models import ConnectUser

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


class SuperusetUserUploadException(Exception):
    pass


class ConnectUserSupersetExporter:
    def __init__(self):
        self.session = requests.Session()
        config = getattr(settings, "SUPERSET_UPLOAD_CONFIG", {})
        self.base_url = config.get("base_url") or ""
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.database_id = config.get("database_id")
        self.table_name = config.get("table_name", "")
        self.schema = config.get("table_schema", "")

    def run(self):
        if not self.base_url or not self.username or not self.password:
            # Upload not configured
            return

        csv_path = None
        try:
            self.authenticate()
            csv_path = self.generate_csv()
            self.upload(csv_path)
            logger.info("Uploaded ConnectUser csv to Superset")
        finally:
            if csv_path:
                try:
                    csv_path.unlink()
                except FileNotFoundError:
                    pass
                except Exception:
                    logger.warning("Failed to delete temporary file %s", csv_path, exc_info=True)

    def generate_csv(self) -> Path:
        MAX_USER_UPLOAD_LIMIT = 100000
        if ConnectUser.objects.count() > MAX_USER_UPLOAD_LIMIT:
            raise SuperusetUserUploadException(f"ConnectUser count is greater than {MAX_USER_UPLOAD_LIMIT}")

        try:
            tmp = tempfile.NamedTemporaryFile(mode="w", newline="", suffix=".csv", delete=False)
            writer = csv.DictWriter(tmp, fieldnames=CONNECT_USER_DUMP_FIELDS)
            writer.writeheader()
            for user in ConnectUser.objects.all().values(*CONNECT_USER_DUMP_FIELDS).iterator(chunk_size=500):
                writer.writerow({k: self._serialize_value(user[k]) for k in CONNECT_USER_DUMP_FIELDS})
        except Exception:
            tmp.close()
            Path(tmp.name).unlink(missing_ok=True)
            raise
        tmp.close()
        return Path(tmp.name)

    def authenticate(self):
        access_token = self._login()
        self.session.headers.update({"Authorization": f"Bearer {access_token}"})
        csrf_token = self._get_csrf_token()
        self.session.headers.update({"X-CSRFToken": csrf_token, "Referer": f"{self.base_url}/"})

    def _login(self):
        data = self._request(
            "post",
            "/api/v1/security/login",
            json={"username": self.username, "password": self.password, "provider": "db", "refresh": True},
        )
        token = data.get("access_token")
        if not token:
            raise SuperusetUserUploadException("Superset login failed: missing access_token")
        return token

    def _get_csrf_token(self):
        data = self._request(
            "get",
            "/api/v1/security/csrf_token/",
        )
        csrf = data.get("result")
        if not csrf:
            raise SuperusetUserUploadException("Superset CSRF token missing")
        return csrf

    def upload(self, csv_path: Path):
        payload = {
            "table_name": self.table_name,
            "already_exists": "replace",
        }
        if self.schema:
            payload["schema"] = self.schema
        with csv_path.open("rb") as csv_file:
            self._request(
                "post",
                f"/api/v1/database/{self.database_id}/csv_upload/",
                data=payload,
                files={"file": (csv_path.name, csv_file, "text/csv")},
            )

    def _request(self, method: str, path: str, **kwargs):
        url = f"{self.base_url}{path}"
        response = self.session.request(method, url, timeout=60, **kwargs)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _serialize_value(value):
        if value is None:
            return ""
        if isinstance(value, PhoneNumber):
            return value.as_e164
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        return value


@shared_task(name="users.tasks.upload_connect_users_to_superset")
def upload_connect_users_to_superset():
    exporter = ConnectUserSupersetExporter()
    try:
        exporter.run()
    except Exception as exc:
        sentry_sdk.capture_exception(exc)
        logger.exception("Failed to upload ConnectUser dump to Superset")
        raise
