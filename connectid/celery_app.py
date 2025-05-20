import os
from datetime import timedelta

from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "connectid.settings")

app = Celery("connectid")

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

app.conf.beat_schedule = {
    "delete_old_messages": {
        "task": "messaging.task.delete_old_messages",
        "schedule": timedelta(hours=24),
    },
    "resend_notifications_for_undelivered_messages": {
        "task": "messaging.task.resend_notifications_for_undelivered_messages",
        "schedule": timedelta(hours=1),
    },
}
