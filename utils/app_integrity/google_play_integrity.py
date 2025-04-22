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

    def _obtain_verdict(self):
        """Obtain token verdict from Google"""
        pass

    def _analyze_verdict(self, verdict_response):
        """
        Checks the verdict and raises appropriate exceptions if
        the app integrity is compromised.
        """
        pass
