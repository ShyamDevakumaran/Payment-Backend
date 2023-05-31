from django.contrib import admin
from django.contrib.auth.models import Group
from knox.models import AuthToken

admin.site.unregister(AuthToken)
admin.site.unregister(Group)
