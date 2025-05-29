from django.conf import settings
from google.oauth2 import service_account
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.schemas import AccountDetails, AppIntegrity, DeviceIntegrity, RequestDetails, VerdictResponse

APP_PACKAGE_NAME = "org.commcare.dalvik"
GOOGLE_SERVICE_NAME = "playintegrity"


class AppIntegrityService:
    """
    Verifies the application integrity of the app using Google Play Integrity API.
    """

    def __init__(self, token: str, request_hash: str):
        self.token = token
        self.request_hash = request_hash

    def verify_integrity(self):
        """
        Raises an exception if the app integrity is compromised, otherwise does nothing.
        """
        verdict_response = self._obtain_verdict()
        self._analyze_verdict(verdict_response)

    def _obtain_verdict(self) -> VerdictResponse:
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
            try:
                response = service.v1().decodeIntegrityToken(packageName=APP_PACKAGE_NAME, body=body).execute()
            except HttpError:
                raise IntegrityRequestError("Invalid token")

        return VerdictResponse.from_dict(response["tokenPayloadExternal"])

    @property
    def _google_service_account_credentials(self) -> Credentials:
        if not settings.GOOGLE_APPLICATION_CREDENTIALS:
            raise Exception("GOOGLE_APPLICATION_CREDENTIALS must be set")
        return service_account.Credentials.from_service_account_info(
            settings.GOOGLE_APPLICATION_CREDENTIALS,
            scopes=["https://www.googleapis.com/auth/playintegrity"],
        )

    def _analyze_verdict(self, verdict: VerdictResponse):
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
        if request_details.requestPackageName != APP_PACKAGE_NAME:
            raise IntegrityRequestError("Request package name mismatch")

    def _check_app_integrity(self, app_integrity: AppIntegrity):
        if app_integrity.packageName != APP_PACKAGE_NAME:
            raise AppIntegrityError("App package name mismatch")

        # Not sure how important this is, but leaving it commented out for now
        # if app_integrity.appRecognitionVerdict != "PLAY_RECOGNIZED":
        #     raise AppIntegrityError("App not recognized")

    def _check_device_integrity(self, device_integrity: DeviceIntegrity):
        if device_integrity.deviceRecognitionVerdict[0] != "MEETS_DEVICE_INTEGRITY":
            raise DeviceIntegrityError("Device integrity compromised")

    def _check_account_details(self, account_details: AccountDetails):
        verdict = account_details.appLicensingVerdict
        if verdict != "UNEVALUATED" and verdict != "LICENSED":
            raise AccountDetailsError("Account not licensed")
