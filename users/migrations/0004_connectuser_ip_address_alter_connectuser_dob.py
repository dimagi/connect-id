# Generated by Django 4.0.10 on 2023-05-18 17:19

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0003_recoverystatus"),
    ]

    operations = [
        migrations.AddField(
            model_name="connectuser",
            name="ip_address",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="connectuser",
            name="dob",
            field=models.DateField(blank=True, null=True),
        ),
    ]
