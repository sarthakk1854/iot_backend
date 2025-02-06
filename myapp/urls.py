from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import RegisterView, LoginView, DeviceListView,DeviceDetailView, ReportDataView, toggle_device_status,DeviceDataView, DownloadDeviceDataView,get_user_data, SendOTPView, VerifyOTPView, ResetPasswordView

from . import views

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login/', LoginView.as_view(), name='login'),
    path('user/', get_user_data, name='user-data'),
    path('devices/', DeviceListView.as_view(), name='device-list'),
    path('devices/<int:device_id>/', DeviceDetailView.as_view(), name='device-detail'),
    path('devices/<int:device_id>/data/', DeviceDataView.as_view(), name='device-data'),
    path('devices/<int:device_id>/', views.get_device_data, name='get_device_data'),
    path('download/device-data/<int:device_id>/', DownloadDeviceDataView.as_view(), name='download_device_data'),
    path('toggle-device-status/<int:device_id>/', toggle_device_status, name='toggle_device_status'),
    path('reports/', ReportDataView.as_view(), name='report-data'),
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
]
