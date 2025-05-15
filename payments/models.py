from django.db import models
from phonenumber_field.modelfields import PhoneNumberField

from users.models import ConnectUser


class PaymentProfile(models.Model):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

    STATUS_CHOICES = [
        (PENDING, "Pending"),
        (APPROVED, "Approved"),
        (REJECTED, "Rejected"),
    ]

    user = models.OneToOneField(ConnectUser, on_delete=models.CASCADE, related_name="payment_profile")
    phone_number = PhoneNumberField()
    owner_name = models.TextField(max_length=150, blank=True)
    telecom_provider = models.CharField(max_length=50, blank=True, null=True)
    # whether the number is verified using OTP
    is_verified = models.BooleanField(default=False)
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default=PENDING,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
