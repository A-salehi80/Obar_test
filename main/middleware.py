from django.utils.timezone import now
from django.http import HttpResponseForbidden
from .models import IPAttempt
from datetime import timedelta
from .utils import ip_has_three_consecutive_failures,user_has_three_consecutive_user_failures

# here for traking invalid cridential attempes we need middleware

# it blockes ips with more than 3 invalid cridetial attemps


class BlockIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)
        user = getattr(request, 'user', None)

        if user and user.is_authenticated:
            if user_has_three_consecutive_user_failures(user):
                latest_attempt = IPAttempt.objects.filter(user=user).latest('datetime')
                blocked_until = now() - latest_attempt.datetime
                return HttpResponseForbidden(f"User blocked due to 3 consecutive failed attempts. Block duration: {blocked_until}")

        if ip_has_three_consecutive_failures(ip):
            latest_attempt = IPAttempt.objects.filter(ip_address=ip).latest('datetime')
            blocked_until = now() - latest_attempt.datetime
            if blocked_until < timedelta(hours=1):
                return HttpResponseForbidden(f"IP blocked due to 3 consecutive failed attempts. Block duration: {blocked_until}")

        return self.get_response(request)
# getting ip inorder to be able to block more than 3 invalid attemps

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
