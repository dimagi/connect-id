# Generated by Django 4.0.10 on 2023-04-24 18:03

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0002_phonedevice_phonedevice_phone_number_user"),
    ]

    operations = [
        migrations.CreateModel(
            name="RecoveryStatus",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("secret_key", models.TextField()),
                (
                    "step",
                    models.TextField(
                        choices=[
                            ("primary", "Confirm Primary"),
                            ("secondary", "Confirm Secondary"),
                            ("password", "Reset Password"),
                        ]
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, unique=True
                    ),
                ),
            ],
        ),
    ]
