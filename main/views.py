from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import OTP, User,IPAttempt
from .serializers import SendOTPSerializer,VerifyOTPSerializer,RegisterSerializer
from .utils import generate_otp,get_client_ip,has_recent_verified_otp,is_profile_complete
from rest_framework.authtoken.models import Token


class SendOTPView(APIView):
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        phone = serializer.validated_data['phone']

        if User.objects.filter(Phone=phone).exists():
            return Response({
                "detail": "User already exists. Please proceed to login.",
                "new_user": False
            }, status=status.HTTP_200_OK)
        otp_code = generate_otp()
        OTP.objects.create(phone=phone, otp_code=otp_code)

        print(f"OTP sent to {phone}: {otp_code}")
        return Response({
            "detail": "OTP sent successfully.",
            "new_user": True
        }, status=status.HTTP_200_OK)





class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        phone = serializer.validated_data['phone']
        otp_input = serializer.validated_data['otp']
        ip = get_client_ip(request)
        user = User.objects.filter(Phone=phone).first()


        try:
            otp = OTP.objects.filter(phone=phone, otp_code=otp_input, is_used=False).latest('created_at')
        except OTP.DoesNotExist:
            # Log failed attempt
            IPAttempt.objects.create(ip_address=ip,user=user, is_successful=False)
            return Response({"detail": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        if otp.is_expired():
            IPAttempt.objects.create(ip_address=ip, user=user, is_successful=False)
            return Response({"detail": "OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

        # Success: mark OTP and log success
        otp.is_used = True
        otp.save()
        IPAttempt.objects.create(ip_address=ip, user=user, is_successful=True)

        return Response({"detail": "OTP verified successfully"}, status=status.HTTP_200_OK)


class LoginView(APIView):
    def post(self, request):
        phone = request.data.get('phone')
        password = request.data.get('password')

        if not phone or not password:
            return Response({"detail": "Phone and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(Phone=phone)
        except User.DoesNotExist:
            IPAttempt.objects.create(ip_address=get_client_ip(request), is_successful=False)
            return Response({"detail": "User not found."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            IPAttempt.objects.create(ip_address=get_client_ip(request),user=user, is_successful=False)
            return Response({"detail": "Incorrect password."}, status=status.HTTP_400_BAD_REQUEST)

        # Create or retrieve auth token
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            "token": token.key,
            "user": {
                "phone": user.Phone,
            }
        }, status=status.HTTP_200_OK)

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        phone = serializer.validated_data.get('Phone')



        if not has_recent_verified_otp(phone):
            return Response(
                {"detail": "You must verify OTP before completing registration."},
                status=status.HTTP_403_FORBIDDEN
            )


        first_name = serializer.validated_data.get('first_name')
        last_name = serializer.validated_data.get('last_name')
        email = serializer.validated_data.get('email')

        user=User.objects.create(first_name=first_name,last_name=last_name,email=email,Phone=phone)
        user.set_password(serializer.validated_data.get('password'))
        user.save()

        token, _ = Token.objects.get_or_create(user=user)

        return Response({
            "detail": "User registered successfully.",
            "token": token.key,
            "user": {
                "id": user.id,
                "phone": user.Phone,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
            }
        }, status=status.HTTP_201_CREATED)
