from django import forms
from .models import User
from .forms import RegistrationForm, is_valid_password
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.shortcuts import render, redirect
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import login
from django.http import HttpResponse, Http404
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from datetime import timedelta
from django.utils import timezone 
from datetime import datetime, timedelta

def register(request):
    try:
        if request.method == 'POST':
            form = RegistrationForm(request.POST)
            if form.is_valid():
                first_name = form.cleaned_data['first_name']
                last_name = form.cleaned_data['last_name']
                email = form.cleaned_data['email']
                mobile_number = form.cleaned_data['mobile_number']
                password = form.cleaned_data['password']
                hashed_password = make_password(password)

                if not is_valid_password(password):
                    return render(request, 'myapp/registration.html', {'error': 'Invalid password'})

                if User.objects.filter(email=email).exists():
                    return render(request, 'myapp/registration.html', {'error': 'Email already exists'})
                if User.objects.filter(mobile_number=mobile_number).exists():
                    return render(request, 'myapp/registration.html', {'error': 'Mobile number already exists'})

                user = User.objects.create_user(
                    email=email,
                    password=password,
                    mobile_number=mobile_number,
                    first_name=first_name,
                    last_name=last_name,
                )
                user.save()

                return render(request, 'myapp/registration_success.html')

        else:
            form = RegistrationForm()

        return render(request, 'myapp/registration.html', {'form': form})

    except Exception as e:
        return render(request, 'myapp/error.html', {'error': str(e)})

def home(request):
    return render(request, 'myapp/home.html')

def forgot_password(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
            except ObjectDoesNotExist:
                return render(request, 'myapp/forgot_password.html', {'error': 'User with this email does not exist'})

            token = default_token_generator.make_token(user)

            uid = urlsafe_base64_encode(force_str(user.pk).encode('utf-8'))
            expiration_time = timezone.now() + timedelta(hours=24)  
            reset_link = f"{request.scheme}://{request.get_host()}/reset_password/{uid}/{token}/?expires={expiration_time}"

            subject = 'Password Reset'
            message = render_to_string('myapp/password_reset_email.html', {
                'user': user,
                'reset_link': reset_link,
                'domain': get_current_site(request).domain,
            })

            send_mail(subject, message, 'noreply@example.com', [email])
            return render(request, 'myapp/password_reset_sent.html')

    else:
        form = PasswordResetForm()

    return render(request, 'myapp/forgot_password.html', {'form': form})


def reset_password(request, uid, token):
    try:
        user_id = urlsafe_base64_decode(uid).decode('utf-8')
        user = User.objects.get(pk=user_id)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        raise Http404("User does not exist")

    expiration_time_str = request.GET.get('expires') 

    try:
        expiration_time = datetime.fromisoformat(expiration_time_str)
        expiration_time = timezone.make_aware(expiration_time)  
    except ValueError:
        raise Http404("Invalid expiration time format")

    
    current_time = timezone.now()

    print("Current Time:", current_time)
    print("Expiration Time:", expiration_time)
    
    
    if default_token_generator.check_token(user, token) and current_time <= expiration_time:
        login(request, user)
        return render(request, 'myapp/reset_password.html', {'uid': uid, 'token': token})
    else:
        return HttpResponse("Password reset link has expired.")


def reset_password_confirm(request, uid, token):
    if request.method == 'POST':
        form = SetPasswordForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            logout(request)
            return render(request, 'myapp/password_reset_complete.html')
    else:
        form = SetPasswordForm(request.user)

    return render(request, 'myapp/reset_password_confirm.html', {'form': form})

def send_email(request):
    subject = 'Hello, Django Email!'
    message = 'This is a test email sent from a Django project.'
    from_email = 'akshathashivakumar48@gmail.com'
    recipient_list = ['akshatha4shivu@gmail.com']

    send_mail(subject, message, from_email, recipient_list)

    return HttpResponse('Email sent successfully!')
