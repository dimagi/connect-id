import logging

from django.conf import settings
from google.oauth2 import service_account
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build

from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.schemas import AccountDetails, AppIntegrity, DeviceIntegrity, RequestDetails, VerdictResponse

logger = logging.getLogger(__name__)

APP_PACKAGE_NAME = "org.commcare.dalvik"
GOOGLE_SERVICE_NAME = "playintegrity"


class AppIntegrityService:
    """
    Verifies the application integrity of the app using Google Play Integrity API.
    """

    def __init__(self, token: str, request_hash: str, app_package: str | None = None, is_demo_user: bool = False):
        self.token = token
        self.request_hash = request_hash
        self.package_name = app_package or APP_PACKAGE_NAME
        self.is_demo_user = is_demo_user

    def verify_integrity(self):
        """
        Raises an exception if the app integrity is compromised, otherwise does nothing.
        """
        raw_verdict_response = self.obtain_verdict()
        logger.info(f"Integrity token verdict for app({self.package_name}): {raw_verdict_response}")

        self.analyze_verdict(VerdictResponse.from_dict(raw_verdict_response))

    def obtain_verdict(self) -> VerdictResponse:
        """
        This method uses the Google Play Integrity API to decode the integrity token

        Documentation:
        https://github.com/googleapis/google-api-python-client/blob/main/docs/start.md#building-and-calling-a-service
        """
        service_spec = {
            "serviceName": GOOGLE_SERVICE_NAME,
            "version": "v1",
            "credentials": self._google_service_account_credentials,
        }
        with build(**service_spec) as service:
            body = {"integrityToken": self.token}
            response = service.v1().decodeIntegrityToken(packageName=self.package_name, body=body).execute()
        return response["tokenPayloadExternal"]

    @property
    def _google_service_account_credentials(self) -> Credentials:
        if not settings.GOOGLE_APPLICATION_CREDENTIALS:
            raise Exception("GOOGLE_APPLICATION_CREDENTIALS must be set")
        return service_account.Credentials.from_service_account_info(
            settings.GOOGLE_APPLICATION_CREDENTIALS,
            scopes=["https://www.googleapis.com/auth/playintegrity"],
        )

    def analyze_verdict(self, verdict: VerdictResponse):
        """
        Checks the verdict and raises appropriate exceptions if
        the app integrity is compromised.
        """
        self._check_request_details(verdict.requestDetails)
        self._check_app_integrity(verdict.appIntegrity)
        self._check_device_integrity(verdict.deviceIntegrity)
        self._check_account_details(verdict.accountDetails)

    def _check_request_details(self, request_details: RequestDetails):
        if request_details.requestHash != self.request_hash:
            raise IntegrityRequestError("Request hash mismatch")
        if request_details.requestPackageName != self.package_name:
            raise IntegrityRequestError("Request package name mismatch")

    def _check_app_integrity(self, app_integrity: AppIntegrity):
        if app_integrity.packageName != self.package_name:
            raise AppIntegrityError("App package name mismatch")

    def _check_device_integrity(self, device_integrity: DeviceIntegrity):
        verdicts = device_integrity.deviceRecognitionVerdict

        if self.is_demo_user and "MEETS_VIRTUAL_INTEGRITY" in verdicts:
            return

        if "MEETS_DEVICE_INTEGRITY" not in verdicts:
            raise DeviceIntegrityError("Device integrity compromised")

    def _check_account_details(self, account_details: AccountDetails):
        if self.is_demo_user:
            return

        verdict = account_details.appLicensingVerdict
        if verdict == "UNLICENSED":
            raise AccountDetailsError("Account not licensed")
