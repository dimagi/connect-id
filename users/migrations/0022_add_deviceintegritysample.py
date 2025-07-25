# Generated by Django 4.1.7 on 2025-07-22 06:54

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0021_sessionphonedevice_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="DeviceIntegritySample",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("request_id", models.CharField(max_length=255, unique=True)),
                ("device_id", models.CharField(max_length=255)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("is_demo_user", models.BooleanField(default=False)),
                ("google_verdict", models.JSONField()),
                ("passed", models.BooleanField()),
                ("passed_request_check", models.BooleanField()),
                ("passed_app_integrity_check", models.BooleanField()),
                ("passed_device_integrity_check", models.BooleanField()),
                ("passed_account_details_check", models.BooleanField()),
            ],
            options={
                "ordering": ["-created"],
            },
        ),
    ]
