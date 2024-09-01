from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *
import random
import requests
from django.http import HttpResponse
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from .models import LoginAttempt
import user_agents
from django.http import JsonResponse
import uuid
from .models import PendingLoginRequest
from .models import LogoutRecord


@login_required
def Home(request):
    return render(request, 'index.html')

otp_storage = {}

def send_otp(email, otp):
    subject = 'Your OTP Verification Code'
    message = f'Your OTP code is {otp}. Please use this to complete your registration.'
    email_from = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

def RegisterView(request):
    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        user_data_has_error = False

        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, "Username already exists")

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, "Email already exists")

        if len(password) < 5:
            user_data_has_error = True
            messages.error(request, "Password must be at least 5 characters")

        if user_data_has_error:
            return redirect('register')
        else:
            otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP
            otp_storage[email] = {'otp': otp, 'data': {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'email': email,
                'password': password
            }}
            send_otp(email, otp)
            request.session['email'] = email
            messages.info(request, "OTP sent to your email. Please verify.")
            return redirect('otp_verify')

    return render(request, 'register.html')

def OtpVerifyView(request):
    if request.method == "POST":
        otp_entered = request.POST.get('otp')
        email = request.session.get('email')
        
        if email in otp_storage and str(otp_storage[email]['otp']) == otp_entered:
            user_data = otp_storage[email]['data']
            new_user = User.objects.create_user(
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                email=user_data['email'],
                username=user_data['username'],
                password=user_data['password']
            )
            messages.success(request, "Account created successfully. Please login.")
            del otp_storage[email]  # Clear OTP from storage after successful registration
            return redirect('login')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return redirect('otp_verify')

    return render(request, 'otp_verify.html')

def LogoutView(request):

    logout(request)

    return redirect('login')

def ForgotPassword(request):

    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})

            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            email_body = f'Reset your password using the link below:\n\n\n{full_password_reset_url}'
        
            email_message = EmailMessage(
                'Reset your password', # email subject
                email_body,
                settings.EMAIL_HOST_USER, # email sender
                [email] # email  receiver 
            )

            email_message.fail_silently = True
            email_message.send()

            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')

    return render(request, 'forgot_password.html')

def PasswordResetSent(request, reset_id):

    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

def ResetPassword(request, reset_id):

    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Passwords do not match')

            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, 'Password must be at least 5 characters long')

            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)

            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'Reset link has expired')

                password_reset_id.delete()

            if not passwords_have_error:
                user = password_reset_id.user
                user.set_password(password)
                user.save()

                password_reset_id.delete()

                messages.success(request, 'Password reset. Proceed to login')
                return redirect('login')
            else:
                # redirect back to password reset page and display errors
                return redirect('reset-password', reset_id=reset_id)

    
    except PasswordReset.DoesNotExist:
        
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

    return render(request, 'reset_password.html')

def get_ip_address(request):
    return request.META.get('REMOTE_ADDR')

def get_device_info(request):
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    ua = user_agents.parse(user_agent)
    device_type = 'Mobile' if ua.is_mobile else 'Tablet' if ua.is_tablet else 'PC'
    operating_system = ua.os.family
    browser = ua.browser.family
    return device_type, operating_system, browser

def LogoutView(request):
    if request.user.is_authenticated:
        # Save logout details
        logout_record = LogoutRecord.objects.create(
            user=request.user,
            username=request.user.username,
            logout_time=timezone.now()
        )
        logout_record.save()

    # Log the user out
    logout(request)

    return redirect('login')

def CheckApprovalStatus(request):
    if request.user.is_authenticated:
        try:
            pending_request = PendingLoginRequest.objects.get(user=request.user)
            return JsonResponse({'approved': pending_request.is_approved})
        except PendingLoginRequest.DoesNotExist:
            return JsonResponse({'approved': False})
    return JsonResponse({'approved': False})

def LoginView(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        lat = request.POST.get("latitude")
        lon = request.POST.get("longitude")
        location = request.POST.get("location")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Check if there's a pending request
            try:
                pending_request = PendingLoginRequest.objects.get(user=user)
                if pending_request.is_approved:
                    login(request, user)
                    pending_request.delete()  # Remove after login
                    # Save login attempt data to the database
                    ip_address = get_ip_address(request)
                    device_type, operating_system, browser = get_device_info(request)
                    login_time = timezone.now()
                    LoginAttempt.objects.create(
                    user=user,
                    username=username,
                    location=location,
                    exact_location_lat=lat,
                    exact_location_lon=lon,
                    ip_address=ip_address,
                    device_type=device_type,
                    operating_system=operating_system,
                    browser=browser,
                    login_time=login_time
                    )
                    return redirect('home')
                else:
                    messages.info(request, "Login request sent. Waiting for admin approval.")
                    return redirect('login')
            except PendingLoginRequest.DoesNotExist:
                # Create a new pending request
                login_token = str(uuid.uuid4())
                PendingLoginRequest.objects.create(user=user, token=login_token)

                # Send email to admin for approval
                approval_link = request.build_absolute_uri(f'/approve_login/{login_token}/')
                send_mail(
                    'Login Request Approval',
                    f'A user with username {username} is requesting to log in. Click the following link to approve or reject: {approval_link}',
                    settings.DEFAULT_FROM_EMAIL,
                    ['criscallion@gmail.com'],
                    fail_silently=False,
                )
                ip_address = get_ip_address(request)
                device_type, operating_system, browser = get_device_info(request)
                login_time = timezone.now()

                
                messages.info(request, "Login request sent. Waiting for admin approval.")
                return redirect('login')
            

        else:
            messages.error(request, "Invalid login credentials")
            return redirect('login')

    return render(request, 'login.html')

def ApproveLoginView(request, token):
    try:
        pending_request = PendingLoginRequest.objects.get(token=token)
        pending_request.is_approved = True
        pending_request.save()
        return HttpResponse("Login approved. The user is now logged in automatically.")
    except PendingLoginRequest.DoesNotExist:
        return HttpResponse("Invalid or expired approval token.")
