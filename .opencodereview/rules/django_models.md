> These checks are additional to the general Python review. Only raise an issue you are confident is a real defect; confirm the base classes, fields and methods with `file_read` before reporting one.

#### Users and Credentials

`ConnectUser` (`users/models.py`) is the custom user model. The phone number, not the username or email, identifies a user.

- A query, constraint or lookup that treats `phone_number` as unique across all users. It is unique only among active users; deactivated users may share a number
- `recovery_pin` assigned directly, or compared with `==`. Use `set_recovery_pin()` and `check_recovery_pin()`, which hash it like a password
- Code that conflates `is_locked` (a security lock after failed attempts) with `is_active` (account deactivation), such as unlocking a user by setting `is_active`
- A new field holding a secret, key or token that is returned by a serializer, written to logs, or shown in the admin without masking

#### File Storage

- A `FileField` given `storages["<alias>"]` or a storage instance directly. A model `FileField` takes a callable returning a `utils.storage.BucketStorage`, so tests and settings changes reach it (see `messaging/models.py` and `utils/storage.py`)
- A file read or written with boto3 rather than Django's storage API
- A row holding a stored file whose file is not deleted when the row is (`MessageAttachment` does this in `messaging/signals.py`)

#### Messaging

- A change to `MessageStatus` that skips or reorders PENDING -> SENT_TO_SERVICE -> DELIVERED -> CONFIRMED_RECEIVED

#### Do Not Report

- Missing docstrings, `Meta.ordering`, or `__str__`
- Existing fields or models the diff does not touch
