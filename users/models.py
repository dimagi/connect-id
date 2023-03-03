from django.contrib.auth.models import AbstractUser
from django.db import models

from phonenumber_field.modelfields import PhoneNumberField
# Create your models here.

class ConnectUser(AbstractUser):
    phone_number = PhoneNumberField(unique=True)
    phone_validated = models.BooleanField(default=False)
    recovery_phone = PhoneNumberField(blank=True)
    recovery_phone_validated = models.BooleanField(default=False)
    name = models.TextField(max_length=150, blank=True)
    dob = models.DateField()

    # removed from base class
    first_name = None
    last_name = None

    REQUIRED_FIELDS = ["phone_number", "dob", "name"]
