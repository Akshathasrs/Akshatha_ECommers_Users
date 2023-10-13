from django import forms
from django.contrib.auth.hashers import make_password  

class RegistrationForm(forms.Form):
    first_name = forms.CharField(max_length=30)
    last_name = forms.CharField(max_length=30)
    email = forms.EmailField()
    mobile_number = forms.CharField(max_length=15)
    password = forms.CharField(widget=forms.PasswordInput)

    def clean_password(self):
        password = self.cleaned_data['password']

        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")

        return make_password(password)

def is_valid_password(password):
    if len(password) < 8:
        return False
    return True
