"""Storage for model FileFields. Buckets are configured in settings.FILE_STORAGE_BUCKETS.

Code that reads or writes files directly uses storages["<bucket alias>"] when it runs, which is
plain Django. A FileField is the exception: Django calls its storage callable once, when the model
loads, and keeps the result, so a FileField given storages["<alias>"] would ignore any later change
to STORAGES and tests would write to the real bucket. A FileField therefore gets a BucketStorage,
which resolves the alias on first use and again after STORAGES changes, the way Django's own
default_storage does.
"""

from django.core.files.storage import storages
from django.core.signals import setting_changed
from django.dispatch import receiver
from django.utils.functional import LazyObject, empty


class BucketStorage(LazyObject):
    """One bucket's storage from STORAGES, resolved on first use."""

    def __init__(self, alias):
        super().__init__()
        self.__dict__["_alias"] = alias

    def _setup(self):
        self._wrapped = storages[self._alias]


message_attachment_storage = BucketStorage("message_attachments")


def get_message_attachment_storage():
    """Storage callable for MessageAttachment.file, so migrations do not depend on settings."""
    return message_attachment_storage


@receiver(setting_changed)
def reset_bucket_storages(*, setting, **kwargs):
    if setting == "STORAGES":
        message_attachment_storage._wrapped = empty
