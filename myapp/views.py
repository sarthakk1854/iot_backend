import datetime
import csv
from django.forms import ValidationError
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from django.http import HttpResponse
from io import BytesIO
from django.utils import timezone
from django.utils.timezone import make_aware
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Device, DeviceData, SensorData , OTP , User
from .serializers import DeviceDataSerializer, DeviceSerializer,  SendOTPSerializer, VerifyOTPSerializer, ResetPasswordSerializer
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import random, time
import threading ,ssl
from datetime import timedelta 
from rest_framework.permissions import IsAuthenticated
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import make_password

ssl._create_default_https_context = ssl._create_unverified_context

# Register User View
class RegisterView(APIView):
    def post(self, request):
        data = request.data
        
        # Validate password and confirm password
        if data.get('password') != data.get('confirmPassword'):
            return Response({'detail': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if email already exists
        if User.objects.filter(email=data.get('email')).exists():
            return Response({'detail': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create the user
        user = User.objects.create_user(
            username=data.get('email'),
            email=data.get('email'),
            first_name=data.get('firstName'),
            last_name=data.get('lastName'),
            password=data.get('password')
        )
        
        # Generate JWT tokens for the new user
        refresh = RefreshToken.for_user(user)
        return Response({
            'detail': 'User registered successfully',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        }, status=status.HTTP_201_CREATED)

# Login View
class LoginView(APIView):
    def post(self, request):
        data = request.data
        
        # Authenticate the user
        user = authenticate(username=data.get('email'), password=data.get('password'))
        
        if user:
            # Generate JWT tokens for the user
            refresh = RefreshToken.for_user(user)
            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'user': {  # Include user details in response
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                }
            }, status=status.HTTP_200_OK)
        
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_data(request):
    user = request.user
    return Response({
        "id": user.id,
        "username": user.username,
        "email": user.email,
    })
# Device List View
class DeviceListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        devices = Device.objects.filter(user=request.user)  # Get devices for the logged-in user
        serializer = DeviceSerializer(devices, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        data = request.data.copy()
        data['user'] = request.user.id # Automatically associate the device with the logged-in user
        serializer = DeviceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Device Detail View
class DeviceDetailView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, device_id):
        device = get_object_or_404(Device, id=device_id)
        serializer = DeviceSerializer(device)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, device_id):
        device = get_object_or_404(Device, id=device_id)
        serializer = DeviceSerializer(device, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, device_id):
        device = get_object_or_404(Device, id=device_id)
        device.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    def post(self, request):
        # Here we ensure that we are passing the right data to the serializer
        try:
            data = request.data
            # Print out the data for debugging purposes
            print('Received data:', data)

            # Validate the request data manually if needed
            required_fields = ['device_name', 'device_type', 'device_id']  # Replace with your model fields
            for field in required_fields:
                if field not in data:
                    return Response({'error': f'{field} is required'}, status=status.HTTP_400_BAD_REQUEST)

            serializer = DeviceSerializer(data=data)

            if serializer.is_valid():
                device = serializer.save()  # Save the new device
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except ValidationError as e:
            # Catch any validation exceptions and return a response
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Catch other exceptions and return a generic error message
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
# Device Data View
class DeviceDataView(APIView):
    def get(self, request, device_id):
        device = get_object_or_404(Device, id=device_id)
        device_data = DeviceData.objects.filter(device=device).order_by('-timestamp')
        # Serialize the device data and send it in the response
        device_data_serializer = DeviceDataSerializer(device_data, many=True)
        return Response(device_data_serializer.data, status=status.HTTP_200_OK)
    

@csrf_exempt
def get_device_data(request, device_id):
    if request.method == 'GET':
        try:
            data = DeviceData.objects.filter(device_id=device_id).values('timestamp', 'value')
            return JsonResponse({'data': list(data)}, safe=False)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid HTTP method'}, status=400)

# Function to generate sensor data
def generate_sensor_data(device):
    # Continuously generates sensor data every minute while the device is active.
    while Device.objects.filter(id=device.id, status="Active").exists():
        sensor_value = DeviceData.generate_random_data(device.type)
        
        # Create SensorData entry
        sensor_data = SensorData.objects.create(device=device, type=device.type, value=sensor_value)
        
        # Create DeviceData entry (storing latest value in DeviceData table)
        device_data = DeviceData.objects.create(device=device, value=sensor_value, type=device.type,)
        
        # Optionally update the last reading on the device (can be used to track current sensor value)
        device.last_reading = {'value': sensor_value}
        device.save()
        
        # Print the generated data to the terminal
        print(f"Generated Data for Device '{device.name}': Value: {sensor_value}, Timestamp: {device_data.timestamp}")
        
        time.sleep(60)  # Wait for 1 minute
@csrf_exempt
def toggle_device_status(request, device_id):
    if request.method == 'POST':
        try:
            device = Device.objects.get(id=device_id)
            if device.status == 'Inactive':
                device.status = 'Active'
                device.save()

                # Start background thread for generating sensor data
                thread = threading.Thread(target=generate_sensor_data, args=(device,))
                thread.daemon = True
                thread.start()
                
            else:
                device.status = 'Inactive'
                # device.last_reading = None
                device.save()

            return JsonResponse({'status': 'success', 'device_status': device.status, 'last_reading': device.last_reading})
        except Device.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Device not found'}, status=404)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

def generate_pdf(device_data, device_name):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)

    # Set up basic info
    p.setFont("Helvetica", 12)
    p.drawString(100, 800, f"Device Data for {device_name}")
    p.drawString(100, 780, f"Date Range: {device_data[0].timestamp} to {device_data[-1].timestamp}")

    y_position = 750
    for data in device_data:
        p.drawString(100, y_position, f"Timestamp: {data.timestamp}, Value: {data.value}")
        y_position -= 20    

    p.showPage()
    p.save()

    buffer.seek(0)
    return buffer

# Utility function to generate CSV
def generate_csv(device_data, device_name):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{device_name}_data.csv"'
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'Value'])

    for data in device_data:
        writer.writerow([data.timestamp, data.value])

    return response

# API endpoint to download device data as CSV or PDF
class DownloadDeviceDataView(APIView):
    def get(self, request, device_id):
        device = get_object_or_404(Device, id=device_id)
        date_range = request.GET.get('dateRange', 'daily')
        
        # Determine date range
        if date_range == 'daily':
            start_date = datetime.datetime.now() - datetime.timedelta(days=1)
        elif date_range == 'weekly':
            start_date = datetime.datetime.now() - datetime.timedelta(weeks=1)
        elif date_range == 'monthly':
            start_date = datetime.datetime.now() - datetime.timedelta(weeks=4)
        elif date_range == 'yearly':
            start_date = datetime.datetime.now() - datetime.timedelta(weeks=52)
        else:
            return Response({'error': 'Invalid date range'}, status=status.HTTP_400_BAD_REQUEST)

        # Convert to aware datetime for filtering
        start_date = make_aware(datetime.datetime.combine(start_date, datetime.datetime.min.time()))
        end_date = datetime.datetime.now()

        # Filter data by date range
        device_data = DeviceData.objects.filter(device=device, timestamp__range=[start_date, end_date]).order_by('timestamp')

        # Format data for response
        device_data_serializer = DeviceDataSerializer(device_data, many=True)

        # Determine if the user wants CSV or PDF
        file_format = request.GET.get('fileFormat', 'csv').lower()

        if file_format == 'pdf':
            pdf_buffer = generate_pdf(device_data_serializer.data, device.name)
            response = HttpResponse(pdf_buffer, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{device.name}_data.pdf"'
            return response
        elif file_format == 'csv':
            return generate_csv(device_data_serializer.data, device.name)
        else:
            return Response({'error': 'Invalid file format'}, status=status.HTTP_400_BAD_REQUEST)
class ReportDataView(APIView):
    def get(self, request):
        # Get query parameters
        device_name = request.query_params.get('device_name')
        date_range = request.query_params.get('date_range')
        
        if not device_name or not date_range:
            return Response({'error': 'Missing parameters'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the device object from the database
            device = Device.objects.get(name=device_name)
            
            # Get the current time
            end_date = timezone.now()

            # Determine the start date based on the date range
            if date_range == 'daily':
                start_date = end_date - timedelta(days=1)
            elif date_range == 'weekly':
                start_date = end_date - timedelta(weeks=1)
            elif date_range == 'monthly':
                start_date = end_date - timedelta(days=30)
            else:
                return Response({'error': 'Invalid date range'}, status=status.HTTP_400_BAD_REQUEST)

            # Filter the SensorData based on the device and timestamp range
            data = SensorData.objects.filter(device=device, timestamp__range=[start_date, end_date])
            
            # Serialize the data
            serializer = DeviceDataSerializer(data, many=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Device.DoesNotExist:
            return Response({'error': 'Device not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'detail': 'Logged out successfully'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

def generate_otp():
        return str(random.randint(100000, 999999))  # Generates a 6-digit OTP

class SendOTPView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)  # Ensure user exists before using it
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        code = generate_otp()  # Assume you have a function to generate OTP

        OTP.objects.create(user=user, code=code)  # Ensure 'code' is the correct field

        send_mail(
            "Your OTP Code",
            f"Your OTP is {code}",
            "noreply@example.com",
            [email],
            fail_silently=False,
        )

        return Response({"message": "OTP sent successfully"}, status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            user = User.objects.filter(email=email).first()

            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            otp_instance = OTP.objects.filter(user=user, code=otp).first()
            if not otp_instance:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": "OTP verified"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()

            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            user.set_password(serializer.validated_data['new_password'])
            user.save()

            # Generate JWT Token
            refresh = RefreshToken.for_user(user)

            return Response({
                "message": "Password reset successfully",
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh)
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)