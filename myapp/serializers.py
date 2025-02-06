from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from .models import Device, SensorData ,DeviceData,OTP

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']

    def validate(self, data):
        # Check if password and password2 match
        if data['password'] != data['password2']:
            raise serializers.ValidationError({
                'password2': 'Password and Confirm Password do not match.'
            })

        # Return validated data
        return data

    def create(self, validated_data):
        validated_data.pop('password2')  # Remove password2 from data
        user = User.objects.create_user(**validated_data)  # Create user
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User  # Use the built-in User model
        fields = ['id', 'username', 'email', 'first_name', 'last_name']  # Include desired fields



class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = '__all__'



class SensorDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = SensorData
        fields = '__all__'

class DeviceDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceData
        fields = '__all__'

class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data