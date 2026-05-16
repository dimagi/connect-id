from django.db import migrations

PERIODIC_TASKS = [
    {
        "name": "delete_old_messages",
        "task": "messaging.tasks.delete_old_messages",
        "interval": {"every": 24, "period": "hours"},
    },
    {
        "name": "resend_notifications_for_undelivered_messages",
        "task": "messaging.tasks.resend_notifications_for_undelivered_messages",
        "interval": {"every": 1, "period": "hours"},
    },
    {
        "name": "upload_connect_users_to_superset",
        "task": "users.tasks.upload_connect_users_to_superset",
        "crontab": {"minute": "0", "hour": "0"},
    },
]


def create_periodic_tasks(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    for entry in PERIODIC_TASKS:
        kwargs = {
            "name": entry["name"],
            "task": entry["task"],
            "interval": None,
            "crontab": None,
            "solar": None,
            "clocked": None,
        }
        if "interval" in entry:
            schedule, _ = IntervalSchedule.objects.get_or_create(**entry["interval"])
            kwargs["interval"] = schedule
        else:
            schedule, _ = CrontabSchedule.objects.get_or_create(**entry["crontab"])
            kwargs["crontab"] = schedule
        PeriodicTask.objects.update_or_create(name=entry["name"], defaults=kwargs)


def remove_periodic_tasks(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name__in=[entry["name"] for entry in PERIODIC_TASKS]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("messaging", "0007_notification"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(create_periodic_tasks, remove_periodic_tasks),
    ]
