from django.contrib import admin
from .models import PasswordReset
from .models import LoginAttempt

from .models import LogoutRecord
from django.contrib import admin
from .models import PendingLoginRequest

admin.site.register(PasswordReset)

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('user', 'username', 'location', 'ip_address', 'device_type', 'operating_system', 'login_time')
    search_fields = ('username', 'ip_address', 'location')
    list_filter = ('location', 'device_type', 'operating_system', 'login_time')
    readonly_fields = ('user', 'username', 'location', 'ip_address', 'device_type', 'operating_system', 'login_time')

admin.site.register(LogoutRecord)

admin.site.register(PendingLoginRequest)
