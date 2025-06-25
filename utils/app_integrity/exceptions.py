class IntegrityRequestError(Exception):
    code = "INTEGRITY_REQUEST_ERROR"


class AppIntegrityError(Exception):
    code = "APP_INTEGRITY_ERROR"


class DeviceIntegrityError(Exception):
    code = "DEVICE_INTEGRITY_ERROR"


class AccountDetailsError(Exception):
    code = "UNLICENSED_APP_ERROR"
