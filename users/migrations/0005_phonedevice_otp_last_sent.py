# Generated by Django 4.1.7 on 2024-02-16 12:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_connectuser_ip_address_alter_connectuser_dob'),
    ]

    operations = [
        migrations.AddField(
            model_name='phonedevice',
            name='otp_last_sent',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
