# Generated by Django 4.1.7 on 2024-05-14 18:26

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0006_alter_connectuser_recovery_pin"),
    ]

    operations = [
        migrations.AddField(
            model_name="connectuser",
            name="recovery_phone_validation_deadline",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="UserKey",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("key", models.TextField()),
                ("valid", models.BooleanField(default=True)),
                ("created", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
