from django.db import models

from phonenumber_field.modelfields import PhoneNumberField
from users.models import ConnectUser


class PaymentProfile(models.Model):
    user = models.OneToOneField(
        ConnectUser,
        on_delete=models.CASCADE,
        related_name='payment_profile'
    )
    phone_number = PhoneNumberField()
    telecom_provider = models.CharField(max_length=50, blank=True, null=True)
    # whether the number is verified using OTP
    is_verified = models.BooleanField(default=False)
    # whether the number is a valid payment receiver
    is_validated = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
