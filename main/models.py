from django.utils import timezone
import datetime
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from Obar_test.settings import OTP_DURATION
from django.core.validators import RegexValidator
from Obar_test.settings import AUTH_USER_MODEL

class CustomUserManager(BaseUserManager):
    def create_user(self, Phone, password=None, **extra_fields):
        if not Phone:
            raise ValueError("The Phone number must be set")
        user = self.model(Phone=Phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, Phone, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(Phone, password, **extra_fields)

class User(AbstractUser):
    username = None  # Remove default username
    Phone = models.CharField(
        max_length=11,
        unique=True,
        validators=[RegexValidator(regex=r'^\d{11}$', message="Phone must be 11 digits")]
    )

    USERNAME_FIELD = 'Phone'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

class OTP(models.Model):
    phone = models.CharField(max_length=11)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() > self.created_at + OTP_DURATION

class IPAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    user = models.ForeignKey(User, on_delete=models.CASCADE,blank=True, null=True)
    datetime = models.DateTimeField(auto_now_add=True)
    is_successful = models.BooleanField(default=False)