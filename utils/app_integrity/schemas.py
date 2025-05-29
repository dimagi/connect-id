from dataclasses import dataclass, field
from typing import Any


@dataclass
class RequestDetails:
    requestPackageName: str = ""
    requestHash: str = ""
    timestampMillis: str = ""


@dataclass
class AppIntegrity:
    appRecognitionVerdict: str = ""
    packageName: str = ""
    certificateSha256Digest: str = ""
    versionCode: str = ""


@dataclass
class DeviceIntegrity:
    deviceRecognitionVerdict: list = field(default_factory=list)
    recentDeviceActivity: dict[str, Any] = field(default_factory=dict)
    deviceAttributes: str = ""


@dataclass
class AccountDetails:
    appLicensingVerdict: str = ""


@dataclass
class EnvironmentDetails:
    playProtectVerdict: str = ""
    appAccessRiskVerdict: dict[str, Any] = field(default_factory=dict)


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
