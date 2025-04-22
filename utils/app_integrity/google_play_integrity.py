from utils.app_integrity.schemas import AccountDetails, AppIntegrity, DeviceIntegrity, RequestDetails, VerdictResponse


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
        pass

    def _check_app_integrity(self, app_integrity: AppIntegrity):
        pass

    def _check_device_integrity(self, device_integrity: DeviceIntegrity):
        pass

    def _check_account_details(self, account_details: AccountDetails):
        pass
