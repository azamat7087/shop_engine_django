import sys
import random
from datetime import timedelta
from phonenumber_field.modelfields import PhoneNumberField

from django.utils import timezone
from django.db import models, IntegrityError
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, AbstractUser

from rest_framework_simplejwt.tokens import RefreshToken


def get_hex_id():
    return str(hex(random.randint(1, 4294967295)))[2:]


def str_to_class(classname):
    return getattr(sys.modules[__name__], classname)


class UsedID(models.Model):
    id = models.CharField(max_length=8, primary_key=True, unique=True, null=False, default='default')

    def __str__(self):
        return self.id


def set_id():
    while True:
        try:
            return UsedID.objects.create(id=get_hex_id())
        except IntegrityError:
            pass


def get_deadline():
    return timezone.now() + timedelta(days=30)


class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            raise TypeError("Users must have a email")

        user = self.model(
            email=email,
        )

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, password, email):
        user = self.create_user(
            email=email,
            password=password,

        )
        user.is_admin = True
        user.is_staff = True
        user.is_verified = True
        user.is_superuser = True
        user.save(using=self._db)


class Users(AbstractBaseUser):
    id = models.CharField(max_length=8, primary_key=True, unique=True, null=False, default='default')
    full_name = models.CharField(max_length=150, blank=True, null=True)
    username = models.CharField(max_length=70, blank=True, default="Blank")
    email = models.EmailField(max_length=80, unique=True)
    image = models.ImageField(upload_to='images/users/images', blank=True,  null=True)
    phone_number = PhoneNumberField(null=True, blank=True)
    date_joined = models.DateTimeField(verbose_name='date_joined', auto_now_add=True)
    last_login = models.DateTimeField(verbose_name='last_login', auto_now=True)
    last_update = models.DateTimeField(auto_now=True)
    session_expire = models.DateTimeField(default=get_deadline)
    is_admin = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    def has_perm(self, perm, obj=None):
        return self.is_admin

    @staticmethod
    def has_module_perms(app_label):
        return True

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = set_id()
        super(Users, self).save(*args, **kwargs)

    class Meta:
        verbose_name_plural = "Users"
        ordering = ("-date_joined", )
