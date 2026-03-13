# Device Tracking Design

## Problem

PersonalID needs to track which device a user is configured on to:
1. Detect when a user tries to authenticate from a previously configured device
2. Inform users during recovery if their old device was recently active
3. Track device activity timestamps

## Data Model

### New Model: `UserDeviceInfo`

| Field | Type | Notes |
|-------|------|-------|
| `user` | ForeignKey(ConnectUser) | `related_name="devices"` |
| `device` | CharField(255) | e.g. "Google Pixel 7" — format: "{MANUFACTURER} {MODEL}" |
| `password` | CharField(128) | Hashed (Django's `make_password`/`check_password`) |
| `configured_at` | DateTimeField | Set when device config completes |
| `last_accessed` | DateTimeField | Updated on each authenticated request from this device |
| `date_created` | DateTimeField | `auto_now_add=True` |

Methods:
- `set_password(raw_password)` — hashes and stores
- `check_password(raw_password)` — validates against hash

Each device has its own password. A user will have a small number of devices, and almost always uses the latest one.

### New Field on `ConfigurationSession`

- `device` (CharField, 255, blank=True, default="") — stores the device string sent in `start_configuration`

## Configuration Flow

### `start_configuration`
- Accept `device` field from request data
- Store on `ConfigurationSession`

### `complete_profile` (new user setup)
- After `user.save()`, create `UserDeviceInfo` with:
  - `user`, `device` from `request.auth.device`
  - `password` = hashed version of the generated password
  - `configured_at` = now, `last_accessed` = now

### `confirm_backup_code` (recovery)
- After setting new password, create `UserDeviceInfo` with same fields as above
- Compare `request.auth.device` (new) against user's most recent `UserDeviceInfo.device` (old)
- If different and old device's `last_accessed` is within 30 days:
  - Include `old_device` and `old_device_last_accessed` in response
- Otherwise: response unchanged

## Tracking `last_accessed`

### Shared Utility (`users/device_utils.py`)

```python
def find_device_for_password(user, raw_password):
    """Iterate UserDeviceInfo records ordered by last_accessed desc.
    Return the one whose password matches, or None."""

def update_device_last_accessed(user, raw_password):
    """Find matching device and update its last_accessed timestamp."""
```

### OAuth Token Requests

Override `validate_user` in `ConnectOAuth2Validator`. On successful auth, call `update_device_last_accessed(user, password)`.

### Basic Auth Views

New `DeviceBasicAuthentication` class in `users/auth.py`:
- Extends `BasicAuthentication`
- After successful `authenticate_credentials`, calls `update_device_last_accessed(user, password)`
- Handles `LOGIN_FROM_DIFFERENT_DEVICE` detection on failure

Replace `rest_framework.authentication.BasicAuthentication` with `DeviceBasicAuthentication` in `DEFAULT_AUTHENTICATION_CLASSES` in settings.

## Failed Auth: `LOGIN_FROM_DIFFERENT_DEVICE`

When authentication fails (in both `DeviceBasicAuthentication` and `ConnectOAuth2Validator`):

1. Look up user by username
2. Iterate `UserDeviceInfo` records (ordered by `last_accessed` desc), check password against each
3. If match found on a non-latest device:
   - If latest device's `configured_at` < 30 days ago: return `LOGIN_FROM_DIFFERENT_DEVICE`
   - If >= 30 days: return standard auth failure
4. If no match on any device: standard auth failure

New error code `LOGIN_FROM_DIFFERENT_DEVICE` added to `users/const.py`.

## Files Modified

- `users/models.py` — new `UserDeviceInfo` model, new `device` field on `ConfigurationSession`
- `users/device_utils.py` — new file, shared device lookup utilities
- `users/auth.py` — new `DeviceBasicAuthentication` class
- `users/oauth.py` — override `validate_user` on `ConnectOAuth2Validator`
- `users/views.py` — modify `start_configuration`, `complete_profile`, `confirm_backup_code`
- `users/const.py` — add `LOGIN_FROM_DIFFERENT_DEVICE` error code
- `connectid/settings.py` — replace `BasicAuthentication` in `DEFAULT_AUTHENTICATION_CLASSES`
- New migration for `UserDeviceInfo` model and `ConfigurationSession.device` field
