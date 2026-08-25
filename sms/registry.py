from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from sms.base import BaseSmsVendor
from sms.vendors.twilio import TwilioVendor

VENDORS: dict[str, type[BaseSmsVendor]] = {
    TwilioVendor.name: TwilioVendor,
}

DEFAULT_VENDOR = TwilioVendor.name


def get_vendor(name: str) -> BaseSmsVendor:
    if name not in VENDORS:
        raise ImproperlyConfigured(f"Unknown SMS vendor {name!r}. Known vendors: {sorted(VENDORS)}")

    config = settings.SMS_VENDORS.get(name)
    if config is None:
        raise ImproperlyConfigured(f"No SMS_VENDORS entry for vendor {name!r}")

    try:
        return VENDORS[name](**config)
    except Exception as e:
        raise ImproperlyConfigured(f"Could not build SMS vendor {name!r} from SMS_VENDORS[{name!r}]: {e}") from e
