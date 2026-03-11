from datetime import timedelta

from django.utils.timezone import now


def find_device_for_password(user, raw_password):
    """Iterate UserDeviceInfo records ordered by last_accessed desc.
    Return the one whose password matches, or None."""
    for device_info in user.devices.all():
        if device_info.check_password(raw_password):
            return device_info
    return None


def update_device_last_accessed(user, raw_password):
    """Find matching device and update its last_accessed timestamp."""
    device_info = find_device_for_password(user, raw_password)
    if device_info:
        device_info.last_accessed = now()
        device_info.save(update_fields=["last_accessed"])


def check_login_from_different_device(user, raw_password):
    """Check if a failed login password belongs to a non-latest device
    and the latest device was last accessed less than 30 days ago.

    Returns True if LOGIN_FROM_DIFFERENT_DEVICE should be returned."""
    devices = list(user.devices.all())
    if not devices:
        return False

    latest_device = devices[0]
    matched_device = None
    for device_info in devices:
        if device_info.check_password(raw_password):
            matched_device = device_info
            break

    if matched_device is None:
        return False

    if matched_device == latest_device:
        return False

    return latest_device.last_accessed > now() - timedelta(days=30)
