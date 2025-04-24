import random,string
from .models import IPAttempt
from datetime import timedelta
from django.utils import timezone
from .models import OTP

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(user, otp_code):
    pass

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def ip_has_three_consecutive_failures(ip):
    attempts = IPAttempt.objects.filter(ip_address=ip).order_by('-datetime')[:3]

    # If we have less than 3 attempts, not to block
    if len(attempts) < 3:
        return False

    # Check if all 3 are unsuccessful
    return all(not attempt.is_successful for attempt in attempts)

def user_has_three_consecutive_user_failures(user):
    attempts = IPAttempt.objects.filter(user=user).order_by('-datetime')[:3]

    if len(attempts) < 3:
        return False

    return all(not attempt.is_successful for attempt in attempts)

def has_recent_verified_otp(phone, minutes=5):
    time_threshold = timezone.now() - timedelta(minutes=minutes)
    return OTP.objects.filter(
        phone=phone,
        is_used=True,
        created_at__gte=time_threshold
    ).exists()

def is_profile_complete(user):
    return (
        bool(user.first_name and user.last_name and user.email)
        and user.has_usable_password()
    )