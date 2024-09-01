from django.db import models
from django.contrib.auth.models import User
import uuid
from django.utils import timezone

class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_when = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username} at {self.created_when}"   

class LoginAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=150)
    location = models.CharField(max_length=100)  # Country
    exact_location_lat = models.FloatField(null=True, blank=True)
    exact_location_lon = models.FloatField(null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    device_type = models.CharField(max_length=50)
    operating_system = models.CharField(max_length=50)
    browser = models.CharField(max_length=100, null=True, blank=True)
    login_time = models.DateTimeField(auto_now_add=True)  # Automatically set the current time

    def __str__(self):
        return f"Login attempt by {self.username} at {self.login_time}"

class LogoutRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=150)
    logout_time = models.DateTimeField()

    def __str__(self):
        return f"Logout by {self.username} at {self.logout_time}"

class PendingLoginRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    is_approved = models.BooleanField(default=False)
