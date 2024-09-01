from django.urls import path
from . import views
from .views import RegisterView, OtpVerifyView  
from .views import LoginView, ApproveLoginView
from .views import CheckApprovalStatus


urlpatterns = [
    path('', views.Home, name='home'),
    path('register/', views.RegisterView, name='register'),
    path('login/', views.LoginView, name='login'),
    path('logout/', views.LogoutView, name='logout'),
    path('forgot-password/', views.ForgotPassword, name='forgot-password'),
    path('password-reset-sent/<str:reset_id>/', views.PasswordResetSent, name='password-reset-sent'),
    path('reset-password/<str:reset_id>/', views.ResetPassword, name='reset-password'),
    path('otp-verify/', OtpVerifyView, name='otp_verify'),
    path('approve_login/<str:token>/', ApproveLoginView, name='approve_login'),
    path('check_approval_status/', CheckApprovalStatus, name='check_approval_status'),
    # Add other URL patterns here
]

