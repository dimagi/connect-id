import base64
import hashlib
import json
import logging
import time
from collections.abc import Mapping

from django.conf import settings
from django.core.cache import caches
from google.oauth2 import service_account
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build

from users.models import DeviceIntegritySample
from utils.app_integrity.exceptions import (
    AccountDetailsError,
    AppIntegrityError,
    DeviceIntegrityError,
    DuplicateSampleRequestError,
    IntegrityRequestError,
)
from utils.app_integrity.schemas import AccountDetails, AppIntegrity, DeviceIntegrity, RequestDetails, VerdictResponse

logger = logging.getLogger(__name__)

APP_PACKAGE_NAME = "org.commcare.dalvik"
GOOGLE_SERVICE_NAME = "playintegrity"

# How old a token's verdict may be. The app fetches a token right before the request it is for.
MAX_TOKEN_AGE_SECONDS = 10 * 60
# Tokens already used, in the cache every worker shares. A token is accepted up to MAX_TOKEN_AGE_SECONDS
# either side of now, so it is remembered for the whole of that window.
USED_TOKEN_CACHE_ALIAS = "rate_limit"
USED_TOKEN_TTL_SECONDS = 2 * MAX_TOKEN_AGE_SECONDS


def compute_request_hashes(raw_body: bytes | None, data: Mapping) -> set[str]:
    """The hashes the Android app could have put in the integrity token for this request.

    The app hashes `JSONObject(body).toString()` and posts the same map through Gson. The two agree byte for
    byte unless a value has characters only one of them escapes ("/" by JSONObject; <, >, &, = and ' by
    Gson), so the raw body almost always gives the hash. For the rest, rebuild what JSONObject writes from
    the parsed body: compact JSON in the order the keys arrived, "/" escaped as "\\/".
    """
    serialized = json.dumps(dict(data.items()), ensure_ascii=False, separators=(",", ":")).replace("/", "\\/")
    hashes = {_sha256_base64(serialized.encode())}
    if raw_body is not None:
        hashes.add(_sha256_base64(raw_body))
    return hashes


def _sha256_base64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


class AppIntegrityService:
    """
    Verifies the application integrity of the app using Google Play Integrity API.
    """

    def __init__(
        self,
        token: str,
        request_hash: str,
        app_package: str | None = None,
        is_demo_user: bool = False,
        expected_request_hashes: set[str] | None = None,
        enforce_request_binding: bool = False,
    ):
        """`expected_request_hashes` are the hashes of the request the token arrived with (see
        compute_request_hashes). Given, the token must have been made for that request, recently; unless
        `enforce_request_binding`, a token that wasn't is only logged.
        """
        self.token = token
        self.request_hash = request_hash
        self.package_name = app_package or APP_PACKAGE_NAME
        self.is_demo_user = is_demo_user
        self.expected_request_hashes = expected_request_hashes
        self.enforce_request_binding = enforce_request_binding
        self.replayed = False

    @property
    def evaluators(self):
        """
        Returns a list of functions that evaluate the verdict.
        The order of evaluation matters, as some checks depend on previous ones.
        """
        return [
            lambda x: self.check_request_details(x.requestDetails),
            lambda x: self.check_request_binding(x.requestDetails),
            lambda x: self.check_app_integrity(x.appIntegrity),
            lambda x: self.check_device_integrity(x.deviceIntegrity),
            lambda x: self.check_account_details(x.accountDetails),
        ]

    def verify_integrity(self):
        """
        Raises an exception if the app integrity is compromised, otherwise does nothing.
        """
        if self.expected_request_hashes is not None:
            self.replayed = not self._claim_token()
            if self.replayed and self.enforce_request_binding:
                # Rejected before Google, so replays don't use up the decode quota.
                self._binding_failed(["replayed"])
        raw_verdict = self.obtain_verdict()
        self.analyze_verdict(self.parse_raw_verdict(raw_verdict))

    def obtain_verdict(self) -> dict:
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

    def parse_raw_verdict(self, raw_verdict: dict) -> VerdictResponse:
        logger.info(f"Integrity token verdict for app({self.package_name}): {raw_verdict}")
        return VerdictResponse.from_dict(raw_verdict)

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
        [evaluator(verdict) for evaluator in self.evaluators]

    def check_request_details(self, request_details: RequestDetails):
        if request_details.requestHash != self.request_hash:
            raise IntegrityRequestError("Request hash mismatch")
        if request_details.requestPackageName != self.package_name:
            raise IntegrityRequestError("Request package name mismatch")

    def check_request_binding(self, request_details: RequestDetails):
        """Check the token was made for this request, recently, and hasn't been used before.

        check_request_details compares the token with the hash header, which the client also chooses, so
        on its own one genuine token can be replayed with any phone number for as long as Google decodes it.
        """
        if self.expected_request_hashes is None:
            return

        problems = ["replayed"] if self.replayed else []
        if request_details.requestHash not in self.expected_request_hashes:
            problems.append("hash_mismatch")
        age_seconds = _age_seconds(request_details.timestampMillis)
        if age_seconds is None or abs(age_seconds) > MAX_TOKEN_AGE_SECONDS:
            problems.append("stale")
        if problems:
            self._binding_failed(problems, age_seconds, request_details.requestHash)

    def _claim_token(self) -> bool:
        """Record the token as used. False if it already was: the same token, sent again.

        Without this, a token passes binding as often as it is sent with the same body for as long as it is
        fresh, and each pass counts towards the country's configuration session limit.
        """
        key = f"integrity_token:{hashlib.sha256(self.token.encode()).hexdigest()}"
        try:
            return caches[USED_TOKEN_CACHE_ALIAS].add(key, 1, USED_TOKEN_TTL_SECONDS)
        except Exception:
            # Failing closed would stop every registration while the cache is down.
            logger.exception("Used integrity token cache unavailable; not checking for a replay")
            return True

    def _binding_failed(self, problems: list[str], age_seconds: int | None = None, token_request_hash=None):
        """Log a token that isn't bound to this request, and reject it if enforcing."""
        fields = {
            "problems": ",".join(problems),
            "enforced": self.enforce_request_binding,
            "age_seconds": age_seconds,
            # Not secret, and the same value across requests is what a replayed token looks like.
            "token_request_hash": token_request_hash,
        }
        logger.warning(
            " ".join(["integrity_request_binding_failed", *(f"{name}={value}" for name, value in fields.items())]),
            extra={"app_integrity": fields},
        )
        if self.enforce_request_binding:
            raise IntegrityRequestError("Token not made for this request")

    def check_app_integrity(self, app_integrity: AppIntegrity):
        if app_integrity.packageName != self.package_name:
            raise AppIntegrityError("App package name mismatch")

    def check_device_integrity(self, device_integrity: DeviceIntegrity):
        verdicts = device_integrity.deviceRecognitionVerdict

        if self.is_demo_user and "MEETS_VIRTUAL_INTEGRITY" in verdicts:
            return

        if "MEETS_DEVICE_INTEGRITY" not in verdicts:
            raise DeviceIntegrityError("Device integrity compromised")

    def check_account_details(self, account_details: AccountDetails):
        if self.is_demo_user:
            return

        verdict = account_details.appLicensingVerdict
        if verdict == "UNLICENSED":
            raise AccountDetailsError("Account not licensed")

    def log_sample_request(self, request_id: str, device_id: str):
        """
        Performs a sampling request to log the integrity check results.
        """
        if DeviceIntegritySample.objects.filter(request_id=request_id).exists():
            raise DuplicateSampleRequestError("Duplicate sample request")

        raw_verdict = self.obtain_verdict()
        verdict = self.parse_raw_verdict(raw_verdict)

        passed_request_check = True
        passed_app_integrity_check = True
        passed_device_integrity_check = True
        passed_account_details_check = True

        for evaluator in self.evaluators:
            try:
                evaluator(verdict)
            except IntegrityRequestError:
                passed_request_check = False
            except AppIntegrityError:
                passed_app_integrity_check = False
            except DeviceIntegrityError:
                passed_device_integrity_check = False
            except AccountDetailsError:
                passed_account_details_check = False

        check_passed = (
            passed_request_check
            and passed_app_integrity_check
            and passed_device_integrity_check
            and passed_account_details_check
        )

        return DeviceIntegritySample.objects.create(
            request_id=request_id,
            device_id=device_id,
            is_demo_user=self.is_demo_user,
            google_verdict=raw_verdict,
            passed=check_passed,
            passed_request_check=passed_request_check,
            passed_app_integrity_check=passed_app_integrity_check,
            passed_device_integrity_check=passed_device_integrity_check,
            passed_account_details_check=passed_account_details_check,
        )


def _age_seconds(timestamp_millis: str) -> int | None:
    try:
        return int(time.time() - int(timestamp_millis) / 1000)
    except (TypeError, ValueError):
        return None
