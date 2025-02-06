# Generated by Django 5.1.4 on 2025-01-23 11:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0004_alter_sensordata_device_alter_sensordata_timestamp_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='type',
            field=models.CharField(choices=[('Temperature Sensor', 'Temperature Sensor'), ('Humidity Sensor', 'Humidity Sensor'), ('Motion Sensor', 'Motion Sensor')], max_length=50),
        ),
    ]
