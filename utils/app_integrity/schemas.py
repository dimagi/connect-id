from dataclasses import dataclass


@dataclass
class RequestDetails:
    requestPackageName: str
    requestHash: str
    timestampMillis: str


@dataclass
class AppIntegrity:
    appRecognitionVerdict: str


@dataclass
class DeviceIntegrity:
    deviceRecognitionVerdict: str


@dataclass
class AccountDetails:
    appLicensingVerdict: str


@dataclass
class VerdictResponse:
    requestDetails: RequestDetails
    appIntegrity: AppIntegrity
    deviceIntegrity: DeviceIntegrity
    accountDetails: AccountDetails
