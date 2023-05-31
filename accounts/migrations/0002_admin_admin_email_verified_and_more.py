# Generated by Django 4.1.7 on 2023-04-08 11:30

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='admin',
            name='admin_email_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='customer',
            name='customer_email_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='customer',
            name='customer_mobile_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name='AdminOTP',
            fields=[
                ('id_otp', models.BigAutoField(primary_key=True, serialize=False)),
                ('email_id', models.EmailField(max_length=254)),
                ('otp_code', models.CharField(max_length=6)),
                ('creation_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('expiry', models.DateTimeField()),
                ('admin', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='otp_set', to='accounts.admin')),
            ],
            options={
                'db_table': 'admin_otp',
            },
        ),
    ]