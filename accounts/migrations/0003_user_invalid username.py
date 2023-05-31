# Generated by Django 4.1.7 on 2023-04-14 14:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_admin_admin_email_verified_and_more'),
    ]

    operations = [
        migrations.AddConstraint(
            model_name='user',
            constraint=models.CheckConstraint(check=models.Q(('username__regex', '^\\w(?:\\w|[.-](?=\\w))*$')), name='Invalid username', violation_error_message="Username must only contain alphanumeric characters, '@', '#', '-', '_', and '.'"),
        ),
    ]