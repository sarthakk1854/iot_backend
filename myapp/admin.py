from django.contrib import admin
from .models import Device, SensorData, DeviceData 

# Registering Device
@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('id' ,'user_id', 'name', 'type', 'status', 'last_reading', 'created_at', 'updated_at')
    search_fields = ('name', 'type')

# Registering SensorData
@admin.register(SensorData)
class SensorDataAdmin(admin.ModelAdmin):
    list_display = ('device', 'type', 'value', 'timestamp')
    search_fields = ('device__name', 'type')

# Registering DeviceData
@admin.register(DeviceData)
class DeviceDataAdmin(admin.ModelAdmin):
    list_display = ('device', 'type','value', 'timestamp')
    search_fields = ('device__name','type')
    ordering = ('-timestamp',)  # To show the latest data first
