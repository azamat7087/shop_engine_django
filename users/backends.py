from django.contrib.auth.backends import ModelBackend
from .models import Users
from django.db.models import Q


class CustomAuthenticationBackend:
    @staticmethod
    def authenticate(request, email_or_phone=None, password=None):
        try:
            user = Users.objects.get(
                Q(email=email_or_phone) | Q(phone_number=email_or_phone)
            )
            pwd_valid = user.check_password(password)
            if pwd_valid:
                return user
            return None
        except Users.DoesNotExist:
            return None

    @staticmethod
    def get_user(user_id):
        try:
            return Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            return None
