from django.db import transaction
from django.db.models.signals import post_delete
from django.dispatch import receiver

from messaging.models import MessageAttachment


@receiver(post_delete, sender=MessageAttachment)
def delete_attachment_file(sender, instance, **kwargs):
    """Delete the stored file once the row's deletion commits, however the row was deleted.

    Covers direct deletes and cascades from a message, channel or user. Nothing is deleted if the
    transaction rolls back. A storage failure is logged rather than raised, since the row is
    already gone; the bucket's lifecycle rule is the backstop for anything left behind.
    """
    if not instance.file:
        return
    storage, name = instance.file.storage, instance.file.name
    transaction.on_commit(lambda: storage.delete(name), robust=True)
