# Generated by Django 4.1.7 on 2024-04-24 18:22

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0004_connectuser_ip_address_alter_connectuser_dob"),
    ]

    operations = [
        migrations.AddField(
            model_name="connectuser",
            name="recovery_pin",
            field=models.CharField(max_length=128, null=True),
        ),
    ]
