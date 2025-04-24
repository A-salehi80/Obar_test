from django.contrib.auth import get_user_model
from rest_framework import serializers
User=get_user_model()
class SendOTPSerializer(serializers.Serializer):
    phone = serializers.CharField(min_length=11, max_length=11)

    def validate_phone(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Phone number must contain digits only.")
        return value

class VerifyOTPSerializer(serializers.Serializer):
    phone = serializers.CharField(min_length=11, max_length=11)
    otp = serializers.CharField(min_length=6, max_length=6)

    def validate_phone(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Phone number must contain only digits.")
        return value

    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits.")
        return value

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ['Phone', 'first_name', 'last_name', 'email', 'password']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)  # securely hash the password
        user.save()
        return user