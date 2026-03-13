# Device Tracking Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Track user devices across configuration, authentication, and recovery flows to detect login attempts from previously configured devices.

**Architecture:** New `UserDeviceInfo` model stores device info + hashed password per configuration. Shared utility functions handle device lookup by password. Custom DRF auth class and OAuth validator hook into auth flows to update timestamps and detect cross-device login attempts.

**Tech Stack:** Django 4.1, Django REST Framework, django-oauth-toolkit, oauthlib, pytest, Factory Boy

---

### Task 1: Add `UserDeviceInfo` Model and `ConfigurationSession.device` Field

**Files:**
- Modify: `users/models.py`
- Modify: `users/factories.py`
- Test: `users/tests/test_models.py`

**Step 1: Write the failing test**

Create `users/tests/test_models.py` (or append if it exists):

```python
import pytest
from django.contrib.auth.hashers import check_password

from users.factories import UserDeviceInfoFactory


@pytest.mark.django_db
class TestUserDeviceInfo:
    def test_set_password_hashes(self):
        device_info = UserDeviceInfoFactory(raw_password="mypassword")
        assert device_info.password != "mypassword"
        assert check_password("mypassword", device_info.password)

    def test_check_password(self):
        device_info = UserDeviceInfoFactory(raw_password="mypassword")
        assert device_info.check_password("mypassword")
        assert not device_info.check_password("wrongpassword")

    def test_fields(self):
        device_info = UserDeviceInfoFactory()
        assert device_info.user is not None
        assert device_info.device == "Google Pixel 7"
        assert device_info.configured_at is not None
        assert device_info.last_accessed is not None
        assert device_info.date_created is not None
```

**Step 2: Run test to verify it fails**

Run: `pytest users/tests/test_models.py::TestUserDeviceInfo -v`
Expected: FAIL — `UserDeviceInfoFactory` does not exist

**Step 3: Write the model and factory**

In `users/models.py`, add after the `DeviceIntegritySample` class (around line 350):

```python
class UserDeviceInfo(models.Model):
    user = models.ForeignKey("ConnectUser", on_delete=models.CASCADE, related_name="devices")
    device = models.CharField(max_length=255)
    password = models.CharField(max_length=128)
    configured_at = models.DateTimeField()
    last_accessed = models.DateTimeField()
    date_created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-last_accessed"]

    def set_password(self, raw_password):
        from django.contrib.auth.hashers import make_password
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        from django.contrib.auth.hashers import check_password
        return check_password(raw_password, self.password)
```

Add `device` field to `ConfigurationSession` (after `device_id` field, around line 274):

```python
device = models.CharField(max_length=255, blank=True, default="")
```

In `users/factories.py`, add import and factory:

```python
from users.models import UserDeviceInfo

class UserDeviceInfoFactory(DjangoModelFactory):
    class Meta:
        model = UserDeviceInfo
        exclude = ["raw_password"]

    user = factory.SubFactory(UserFactory)
    device = "Google Pixel 7"
    configured_at = factory.LazyFunction(now)
    last_accessed = factory.LazyFunction(now)
    raw_password = "testpass"

    @factory.lazy_attribute
    def password(self):
        from django.contrib.auth.hashers import make_password
        return make_password(self.raw_password)
```

**Step 4: Generate migration**

Run: `python manage.py makemigrations users`

**Step 5: Run test to verify it passes**

Run: `pytest users/tests/test_models.py::TestUserDeviceInfo -v`
Expected: PASS

**Step 6: Commit**

```bash
git add users/models.py users/factories.py users/tests/test_models.py users/migrations/
git commit -m "feat: add UserDeviceInfo model and device field on ConfigurationSession"
```

---

### Task 2: Add Error Code and Device Utility Functions

**Files:**
- Modify: `users/const.py`
- Create: `users/device_utils.py`
- Test: `users/tests/test_device_utils.py`

**Step 1: Add error code**

In `users/const.py`, add to the `ErrorCodes` class:

```python
LOGIN_FROM_DIFFERENT_DEVICE = "LOGIN_FROM_DIFFERENT_DEVICE"
```

**Step 2: Write the failing tests**

Create `users/tests/test_device_utils.py`:

```python
from datetime import timedelta

import pytest
from django.utils.timezone import now

from users.device_utils import check_login_from_different_device, find_device_for_password, update_device_last_accessed
from users.factories import UserDeviceInfoFactory, UserFactory


@pytest.mark.django_db
class TestFindDeviceForPassword:
    def test_finds_matching_device(self):
        user = UserFactory()
        device = UserDeviceInfoFactory(user=user, raw_password="password1")
        result = find_device_for_password(user, "password1")
        assert result == device

    def test_returns_none_for_wrong_password(self):
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="password1")
        result = find_device_for_password(user, "wrongpassword")
        assert result is None

    def test_finds_correct_device_among_multiple(self):
        user = UserFactory()
        device1 = UserDeviceInfoFactory(
            user=user, raw_password="password1", device="Old Phone",
            last_accessed=now() - timedelta(days=10),
        )
        device2 = UserDeviceInfoFactory(
            user=user, raw_password="password2", device="New Phone",
            last_accessed=now(),
        )
        assert find_device_for_password(user, "password1") == device1
        assert find_device_for_password(user, "password2") == device2

    def test_no_devices(self):
        user = UserFactory()
        assert find_device_for_password(user, "password1") is None


@pytest.mark.django_db
class TestUpdateDeviceLastAccessed:
    def test_updates_last_accessed(self):
        user = UserFactory()
        old_time = now() - timedelta(days=1)
        device = UserDeviceInfoFactory(user=user, raw_password="password1", last_accessed=old_time)
        update_device_last_accessed(user, "password1")
        device.refresh_from_db()
        assert device.last_accessed > old_time

    def test_no_matching_device(self):
        user = UserFactory()
        # Should not raise
        update_device_last_accessed(user, "wrongpassword")


@pytest.mark.django_db
class TestCheckLoginFromDifferentDevice:
    def test_old_device_password_recent_access(self):
        """User tries old device password, new device last accessed < 30 days ago."""
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user, raw_password="old_pass", device="Old Phone",
            last_accessed=now() - timedelta(days=5),
            configured_at=now() - timedelta(days=60),
        )
        UserDeviceInfoFactory(
            user=user, raw_password="new_pass", device="New Phone",
            last_accessed=now(),
            configured_at=now() - timedelta(days=10),
        )
        assert check_login_from_different_device(user, "old_pass") is True

    def test_old_device_password_old_access(self):
        """User tries old device password, but new device last accessed > 30 days ago."""
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user, raw_password="old_pass", device="Old Phone",
            last_accessed=now() - timedelta(days=60),
            configured_at=now() - timedelta(days=120),
        )
        UserDeviceInfoFactory(
            user=user, raw_password="new_pass", device="New Phone",
            last_accessed=now() - timedelta(days=35),
            configured_at=now() - timedelta(days=45),
        )
        assert check_login_from_different_device(user, "old_pass") is False

    def test_current_device_password(self):
        """User tries the latest device's password — not a different device."""
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user, raw_password="current_pass", device="Current Phone",
            last_accessed=now(),
            configured_at=now() - timedelta(days=5),
        )
        assert check_login_from_different_device(user, "current_pass") is False

    def test_no_matching_password(self):
        """Password doesn't match any device."""
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="some_pass")
        assert check_login_from_different_device(user, "unknown_pass") is False

    def test_no_devices(self):
        user = UserFactory()
        assert check_login_from_different_device(user, "any_pass") is False
```

**Step 3: Run test to verify it fails**

Run: `pytest users/tests/test_device_utils.py -v`
Expected: FAIL — `users.device_utils` does not exist

**Step 4: Write the implementation**

Create `users/device_utils.py`:

```python
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
```

**Step 5: Run test to verify it passes**

Run: `pytest users/tests/test_device_utils.py -v`
Expected: PASS

**Step 6: Commit**

```bash
git add users/const.py users/device_utils.py users/tests/test_device_utils.py
git commit -m "feat: add device utility functions and LOGIN_FROM_DIFFERENT_DEVICE error code"
```

---

### Task 3: Modify `start_device_configuration` to Store Device Info

**Files:**
- Modify: `users/views.py:82-122`
- Test: `users/tests/test_views.py`

**Step 1: Write the failing test**

In `users/tests/test_views.py`, add to the existing `TestStartDeviceConfiguration` class (around line 1130):

```python
@skip_app_integrity_check
@patch("users.models.ConfigurationSession.country_code")
def test_device_stored_on_session(self, mock_country_code, client):
    mock_country_code.return_value = None
    phone_number = Faker().phone_number()

    response = client.post(
        reverse("start_device_configuration"),
        data={"phone_number": phone_number, "device": "Google Pixel 7"},
        HTTP_CC_INTEGRITY_TOKEN="token",
        HTTP_CC_REQUEST_HASH="hash",
    )
    assert response.status_code == 200
    token = response.json().get("token")
    session = ConfigurationSession.objects.get(key=token)
    assert session.device == "Google Pixel 7"
```

**Step 2: Run test to verify it fails**

Run: `pytest users/tests/test_views.py::TestStartDeviceConfiguration::test_device_stored_on_session -v`
Expected: FAIL — `ConfigurationSession` has no `device` field or it's empty

**Step 3: Write the implementation**

In `users/views.py`, in `start_device_configuration` (lines 95-101), add `device` to the `ConfigurationSession` constructor:

```python
token_session = ConfigurationSession(
    phone_number=data["phone_number"],
    is_phone_validated=is_demo_user,
    gps_location=data.get("gps_location"),
    invited_user=request.invited_user,
    device_id=data.get("cc_device_id", ""),
    device=data.get("device", ""),
)
```

**Step 4: Run test to verify it passes**

Run: `pytest users/tests/test_views.py::TestStartDeviceConfiguration::test_device_stored_on_session -v`
Expected: PASS

**Step 5: Commit**

```bash
git add users/views.py users/tests/test_views.py
git commit -m "feat: store device string on ConfigurationSession during start_configuration"
```

---

### Task 4: Create `UserDeviceInfo` in `complete_profile`

**Files:**
- Modify: `users/views.py:207-248`
- Test: `users/tests/test_views.py`

**Step 1: Write the failing test**

In `users/tests/test_views.py`, add to `TestCompleteProfileView`:

```python
@patch("users.views.upload_photo_to_s3")
def test_creates_user_device_info(self, mock_upload_photo, authed_client_token, valid_token):
    valid_token.phone_number = "+27729541235"
    valid_token.device = "Samsung Galaxy S24"
    valid_token.save()
    mock_upload_photo.return_value = None

    response = authed_client_token.post(self.url, data=self.post_data)
    assert response.status_code == 200

    user = ConnectUser.objects.get(phone_number=valid_token.phone_number)
    device_info = user.devices.first()
    assert device_info is not None
    assert device_info.device == "Samsung Galaxy S24"
    assert device_info.check_password(response.json()["password"])
    assert device_info.configured_at is not None
    assert device_info.last_accessed is not None
```

**Step 2: Run test to verify it fails**

Run: `pytest users/tests/test_views.py::TestCompleteProfileView::test_creates_user_device_info -v`
Expected: FAIL — no `UserDeviceInfo` created

**Step 3: Write the implementation**

In `users/views.py`, add `UserDeviceInfo` to the imports from `users.models` (around line 19).

In `complete_profile` (after `user.save()` on line 239, before `db_key` line), add:

```python
device_info = UserDeviceInfo(
    user=user,
    device=session.device,
    configured_at=now(),
    last_accessed=now(),
)
device_info.set_password(password)
device_info.save()
```

Ensure `now` is imported from `django.utils.timezone` (check if already imported).

**Step 4: Run test to verify it passes**

Run: `pytest users/tests/test_views.py::TestCompleteProfileView::test_creates_user_device_info -v`
Expected: PASS

**Step 5: Commit**

```bash
git add users/views.py users/tests/test_views.py
git commit -m "feat: create UserDeviceInfo on complete_profile"
```

---

### Task 5: Create/Update `UserDeviceInfo` in `confirm_backup_code` and Return Old Device Info

**Files:**
- Modify: `users/views.py:537-574`
- Test: `users/tests/test_views.py`

**Step 1: Write the failing tests**

In `users/tests/test_views.py`, add to `TestConfirmBackupCodeApi`:

```python
def test_creates_user_device_info_new_device(self, authed_client_token, user, valid_token):
    user.set_recovery_pin("1234")
    user.save()
    valid_token.device = "New Phone"
    valid_token.save()

    response = authed_client_token.post(self.url, data={"recovery_pin": "1234"})
    assert response.status_code == 200

    device_info = user.devices.first()
    assert device_info is not None
    assert device_info.device == "New Phone"
    assert device_info.check_password(response.json()["password"])

def test_updates_existing_device_info_same_device(self, authed_client_token, user, valid_token):
    user.set_recovery_pin("1234")
    user.save()
    valid_token.device = "Same Phone"
    valid_token.save()

    from users.factories import UserDeviceInfoFactory
    old_device = UserDeviceInfoFactory(
        user=user, raw_password="old_pass", device="Same Phone",
        last_accessed=now() - timedelta(days=5),
    )

    response = authed_client_token.post(self.url, data={"recovery_pin": "1234"})
    assert response.status_code == 200

    # Should have updated the existing record, not created a new one
    assert user.devices.count() == 1
    old_device.refresh_from_db()
    assert old_device.check_password(response.json()["password"])

def test_returns_old_device_info_when_different_and_recent(self, authed_client_token, user, valid_token):
    user.set_recovery_pin("1234")
    user.save()
    valid_token.device = "New Phone"
    valid_token.save()

    from users.factories import UserDeviceInfoFactory
    old_time = now() - timedelta(days=5)
    UserDeviceInfoFactory(
        user=user, raw_password="old_pass", device="Old Phone",
        last_accessed=old_time,
    )

    response = authed_client_token.post(self.url, data={"recovery_pin": "1234"})
    assert response.status_code == 200
    data = response.json()
    assert data["old_device"] == "Old Phone"
    assert "old_device_last_accessed" in data

def test_no_old_device_info_when_same_device(self, authed_client_token, user, valid_token):
    user.set_recovery_pin("1234")
    user.save()
    valid_token.device = "Same Phone"
    valid_token.save()

    from users.factories import UserDeviceInfoFactory
    UserDeviceInfoFactory(
        user=user, raw_password="old_pass", device="Same Phone",
        last_accessed=now(),
    )

    response = authed_client_token.post(self.url, data={"recovery_pin": "1234"})
    assert response.status_code == 200
    data = response.json()
    assert "old_device" not in data

def test_no_old_device_info_when_accessed_over_30_days_ago(self, authed_client_token, user, valid_token):
    user.set_recovery_pin("1234")
    user.save()
    valid_token.device = "New Phone"
    valid_token.save()

    from users.factories import UserDeviceInfoFactory
    UserDeviceInfoFactory(
        user=user, raw_password="old_pass", device="Old Phone",
        last_accessed=now() - timedelta(days=31),
    )

    response = authed_client_token.post(self.url, data={"recovery_pin": "1234"})
    assert response.status_code == 200
    data = response.json()
    assert "old_device" not in data
```

**Step 2: Run tests to verify they fail**

Run: `pytest users/tests/test_views.py::TestConfirmBackupCodeApi::test_creates_user_device_info_new_device users/tests/test_views.py::TestConfirmBackupCodeApi::test_updates_existing_device_info_same_device users/tests/test_views.py::TestConfirmBackupCodeApi::test_returns_old_device_info_when_different_and_recent users/tests/test_views.py::TestConfirmBackupCodeApi::test_no_old_device_info_when_same_device users/tests/test_views.py::TestConfirmBackupCodeApi::test_no_old_device_info_when_accessed_over_30_days_ago -v`
Expected: FAIL

**Step 3: Write the implementation**

In `users/views.py`, modify `confirm_backup_code` (lines 562-574). Replace from `password = token_hex(16)` to the `return JsonResponse(...)`:

```python
password = token_hex(16)
user.set_password(password)
user.reset_failed_backup_code_attempts()
user.save()

# Get the old device info before creating/updating
old_device = user.devices.first()

# Create or update device info
if old_device and old_device.device == session.device:
    # Same device — update the existing record
    old_device.set_password(password)
    old_device.last_accessed = now()
    old_device.save()
else:
    # Different device — create a new record
    new_device = UserDeviceInfo(
        user=user,
        device=session.device,
        configured_at=now(),
        last_accessed=now(),
    )
    new_device.set_password(password)
    new_device.save()

response_data = {
    "username": user.username,
    "db_key": UserKey.get_or_create_key_for_user(user).key,
    "password": password,
    "invited_user": session.invited_user,
}

# Check if old device is different and was recently accessed
if old_device and old_device.device != session.device:
    if old_device.last_accessed > now() - timedelta(days=30):
        response_data["old_device"] = old_device.device
        response_data["old_device_last_accessed"] = old_device.last_accessed.isoformat()

return JsonResponse(response_data)
```

Ensure `UserDeviceInfo` is imported and `timedelta` is imported from `datetime`.

**Step 4: Run tests to verify they pass**

Run: `pytest users/tests/test_views.py::TestConfirmBackupCodeApi -v`
Expected: PASS

**Step 5: Commit**

```bash
git add users/views.py users/tests/test_views.py
git commit -m "feat: create/update UserDeviceInfo on recovery and return old device info"
```

---

### Task 6: Add `DeviceBasicAuthentication` Class

**Files:**
- Modify: `users/auth.py`
- Modify: `connectid/settings.py`
- Test: `users/tests/test_auth.py`

**Step 1: Write the failing tests**

Create `users/tests/test_auth.py` (or append if exists):

```python
import base64
from datetime import timedelta

import pytest
from django.test import RequestFactory
from django.utils.timezone import now
from rest_framework.exceptions import AuthenticationFailed

from users.auth import DeviceBasicAuthentication
from users.const import ErrorCodes
from users.factories import UserDeviceInfoFactory, UserFactory


@pytest.mark.django_db
class TestDeviceBasicAuthentication:
    def setup_method(self):
        self.auth = DeviceBasicAuthentication()
        self.factory = RequestFactory()

    def _make_request(self, username, password):
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        return self.factory.get("/", HTTP_AUTHORIZATION=f"Basic {credentials}")

    def test_successful_auth_updates_last_accessed(self):
        user = UserFactory()
        raw_password = "testpass"
        old_time = now() - timedelta(days=1)
        device = UserDeviceInfoFactory(user=user, raw_password=raw_password, last_accessed=old_time)

        request = self._make_request(user.username, raw_password)
        result_user, _ = self.auth.authenticate(request)
        assert result_user == user
        device.refresh_from_db()
        assert device.last_accessed > old_time

    def test_failed_auth_different_device(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user, raw_password="old_pass", device="Old Phone",
            configured_at=now() - timedelta(days=60),
            last_accessed=now() - timedelta(days=5),
        )
        UserDeviceInfoFactory(
            user=user, raw_password="new_pass", device="New Phone",
            configured_at=now() - timedelta(days=10),
            last_accessed=now(),
        )

        request = self._make_request(user.username, "old_pass")
        with pytest.raises(AuthenticationFailed) as exc_info:
            self.auth.authenticate(request)
        assert ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE in str(exc_info.value.detail)

    def test_failed_auth_old_access_no_special_error(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user, raw_password="old_pass", device="Old Phone",
            configured_at=now() - timedelta(days=120),
            last_accessed=now() - timedelta(days=60),
        )
        UserDeviceInfoFactory(
            user=user, raw_password="new_pass", device="New Phone",
            configured_at=now() - timedelta(days=45),
            last_accessed=now() - timedelta(days=35),
        )

        request = self._make_request(user.username, "old_pass")
        with pytest.raises(AuthenticationFailed) as exc_info:
            self.auth.authenticate(request)
        assert ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE not in str(exc_info.value.detail)

    def test_failed_auth_unknown_password(self):
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="some_pass")

        request = self._make_request(user.username, "totally_wrong")
        with pytest.raises(AuthenticationFailed) as exc_info:
            self.auth.authenticate(request)
        assert ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE not in str(exc_info.value.detail)
```

**Step 2: Run test to verify it fails**

Run: `pytest users/tests/test_auth.py::TestDeviceBasicAuthentication -v`
Expected: FAIL — `DeviceBasicAuthentication` does not exist

**Step 3: Write the implementation**

In `users/auth.py`, add imports and the new class:

```python
from users.device_utils import check_login_from_different_device, update_device_last_accessed


class DeviceBasicAuthentication(BasicAuthentication):
    def authenticate_credentials(self, userid, password, request=None):
        try:
            result = super().authenticate_credentials(userid, password, request)
        except exceptions.AuthenticationFailed:
            try:
                user = ConnectUser.objects.get(username=userid, is_active=True)
            except ConnectUser.DoesNotExist:
                raise
            if check_login_from_different_device(user, password):
                raise exceptions.AuthenticationFailed(
                    {"error_code": ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE}
                )
            raise

        user = result[0]
        update_device_last_accessed(user, password)
        return result
```

**Step 4: Update settings**

In `connectid/settings.py`, change `DEFAULT_AUTHENTICATION_CLASSES` (line 180):

```python
"DEFAULT_AUTHENTICATION_CLASSES": [
    "users.auth.DeviceBasicAuthentication",
    "oauth2_provider.contrib.rest_framework.OAuth2Authentication",
],
```

**Step 5: Run tests to verify they pass**

Run: `pytest users/tests/test_auth.py::TestDeviceBasicAuthentication -v`
Expected: PASS

**Step 6: Run full test suite to check for regressions**

Run: `pytest --tb=short`
Expected: All existing tests still pass

**Step 7: Commit**

```bash
git add users/auth.py connectid/settings.py users/tests/test_auth.py
git commit -m "feat: add DeviceBasicAuthentication with device tracking and cross-device detection"
```

---

### Task 7: Override `validate_user` in `ConnectOAuth2Validator`

**Files:**
- Modify: `users/oauth.py`
- Test: `users/tests/test_oauth.py`

**Step 1: Write the failing tests**

Create `users/tests/test_oauth.py`:

```python
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from django.utils.timezone import now
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error

from users.const import ErrorCodes
from users.factories import UserDeviceInfoFactory, UserFactory
from users.oauth import ConnectOAuth2Validator


@pytest.mark.django_db
class TestConnectOAuth2ValidatorUser:
    def setup_method(self):
        self.validator = ConnectOAuth2Validator()

    def test_successful_auth_updates_last_accessed(self):
        user = UserFactory()
        raw_password = "testpass"
        old_time = now() - timedelta(days=1)
        device = UserDeviceInfoFactory(user=user, raw_password=raw_password, last_accessed=old_time)

        request = MagicMock()
        result = self.validator.validate_user(
            user.username, raw_password, client=MagicMock(), request=request
        )
        assert result is True
        device.refresh_from_db()
        assert device.last_accessed > old_time

    def test_failed_auth_different_device_raises_custom_error(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user, raw_password="old_pass", device="Old Phone",
            configured_at=now() - timedelta(days=60),
            last_accessed=now() - timedelta(days=5),
        )
        UserDeviceInfoFactory(
            user=user, raw_password="new_pass", device="New Phone",
            configured_at=now() - timedelta(days=10),
            last_accessed=now(),
        )

        request = MagicMock()
        with pytest.raises(CustomOAuth2Error) as exc_info:
            self.validator.validate_user(
                user.username, "old_pass", client=MagicMock(), request=request
            )
        assert exc_info.value.error == ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE

    def test_failed_auth_no_device_match(self):
        user = UserFactory()
        UserDeviceInfoFactory(user=user, raw_password="some_pass")

        request = MagicMock()
        result = self.validator.validate_user(
            user.username, "totally_wrong", client=MagicMock(), request=request
        )
        assert result is False

    def test_failed_auth_old_access_returns_false(self):
        user = UserFactory()
        UserDeviceInfoFactory(
            user=user, raw_password="old_pass", device="Old Phone",
            configured_at=now() - timedelta(days=120),
            last_accessed=now() - timedelta(days=60),
        )
        UserDeviceInfoFactory(
            user=user, raw_password="new_pass", device="New Phone",
            configured_at=now() - timedelta(days=45),
            last_accessed=now() - timedelta(days=35),
        )

        request = MagicMock()
        result = self.validator.validate_user(
            user.username, "old_pass", client=MagicMock(), request=request
        )
        assert result is False
```

**Step 2: Run test to verify it fails**

Run: `pytest users/tests/test_oauth.py -v`
Expected: FAIL — `validate_user` not overridden

**Step 3: Write the implementation**

Replace `users/oauth.py` with:

```python
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error
from oauth2_provider.oauth2_validators import OAuth2Validator

from users.const import ErrorCodes
from users.device_utils import check_login_from_different_device, update_device_last_accessed
from users.models import ConnectUser


class ConnectOAuth2Validator(OAuth2Validator):
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update({"is_active": "openid", "phone": "openid", "name": "openid"})

    def validate_user(self, username, password, client, request, *args, **kwargs):
        result = super().validate_user(username, password, client, request, *args, **kwargs)
        if result:
            update_device_last_accessed(request.user, password)
        else:
            try:
                user = ConnectUser.objects.get(username=username, is_active=True)
            except ConnectUser.DoesNotExist:
                return result
            if check_login_from_different_device(user, password):
                raise CustomOAuth2Error(
                    error=ErrorCodes.LOGIN_FROM_DIFFERENT_DEVICE,
                    description="Login attempted from a previously configured device.",
                )
        return result

    def get_additional_claims(self, request):
        claims = {}
        claims["sub"] = request.user.username
        claims["name"] = request.user.name
        claims["phone"] = request.user.phone_number.as_e164
        claims["is_active"] = request.user.is_active
        return claims
```

**Step 4: Run tests to verify they pass**

Run: `pytest users/tests/test_oauth.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add users/oauth.py users/tests/test_oauth.py
git commit -m "feat: add device tracking to ConnectOAuth2Validator with LOGIN_FROM_DIFFERENT_DEVICE error"
```

---

### Task 8: Integration Testing and Final Verification

**Files:**
- All modified files

**Step 1: Run the full test suite**

Run: `pytest --tb=short`
Expected: All tests pass

**Step 2: Run pre-commit hooks**

Run: `pre-commit run -a`
Expected: All hooks pass (black, isort, flake8)

**Step 3: Fix any formatting issues**

If pre-commit fails, fix the issues and re-run.

**Step 4: Final commit (only if formatting changes needed)**

```bash
git add -A
git commit -m "chore: formatting fixes for device tracking feature"
```
