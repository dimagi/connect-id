from dataclasses import dataclass
from typing import Any


@dataclass
class RequestDetails:
    requestPackageName: str
    requestHash: str
    timestampMillis: str


@dataclass
class AppIntegrity:
    appRecognitionVerdict: str
    packageName: str
    certificateSha256Digest: str
    versionCode: str


@dataclass
class DeviceIntegrity:
    deviceRecognitionVerdict: list


@dataclass
class AccountDetails:
    appLicensingVerdict: str


@dataclass
class VerdictResponse:
    requestDetails: RequestDetails
    appIntegrity: AppIntegrity
    deviceIntegrity: DeviceIntegrity
    accountDetails: AccountDetails

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerdictResponse":
        return cls(
            requestDetails=RequestDetails(**data.get("requestDetails", {})),
            appIntegrity=AppIntegrity(**data.get("appIntegrity", {})),
            deviceIntegrity=DeviceIntegrity(**data.get("deviceIntegrity", {})),
            accountDetails=AccountDetails(**data.get("accountDetails", {})),
        )
