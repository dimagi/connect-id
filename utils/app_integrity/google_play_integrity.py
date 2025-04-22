from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    IntegrityRequestError,
)
from utils.app_integrity.schemas import AccountDetails, AppIntegrity, DeviceIntegrity, RequestDetails, VerdictResponse

APP_PACKAGE_NAME = "todo"


class AppIntegrityService:
    """
    Verifies the application integrity of the app using Google Play Integrity API.
    """

    def __init__(self, token: str, request_hash: str = None):
        self.token = token
        self.request_hash = request_hash

    def verify_integrity(self):
        verdict_response = self._obtain_verdict()
        self._analyze_verdict(verdict_response)

    def _obtain_verdict(self) -> VerdictResponse:
        """Obtain token verdict from Google"""
        pass

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
        if app_integrity.appRecognitionVerdict != "PLAY_RECOGNIZED":
            raise AppIntegrityError("App not recognized")

    def _check_device_integrity(self, device_integrity: DeviceIntegrity):
        if device_integrity.deviceRecognitionVerdict != "MEETS_DEVICE_INTEGRITY":
            raise DeviceIntegrityError("Device integrity compromised")

    def _check_account_details(self, account_details: AccountDetails):
        if account_details.appLicensingVerdict != "LICENSED":
            raise AccountDetailsError("Account not licensed")
