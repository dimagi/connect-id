# Generated by Django 4.1.7 on 2023-03-28 12:06

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import phonenumber_field.modelfields


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="PhoneDevice",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(help_text="The human-readable name of this device.", max_length=64)),
                ("confirmed", models.BooleanField(default=True, help_text="Is this device ready for use?")),
                ("token", models.CharField(blank=True, max_length=16, null=True)),
                (
                    "valid_until",
                    models.DateTimeField(
                        default=django.utils.timezone.now,
                        help_text="The timestamp of the moment of expiry of the saved token.",
                    ),
                ),
                ("phone_number", phonenumber_field.modelfields.PhoneNumberField(max_length=128, region=None)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddConstraint(
            model_name="phonedevice",
            constraint=models.UniqueConstraint(fields=("phone_number", "user"), name="phone_number_user"),
        ),
    ]
