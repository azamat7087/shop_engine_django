from phonenumber_field.serializerfields import PhoneNumberField

from django.contrib import auth
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

import users.utils as users_utils
import users.models as user_models


class UsersSerializer(serializers.ModelSerializer):

    class Meta:
        model = user_models.Users
        fields = ('id', 'full_name', 'username', 'email', 'image', 'phone_number',)


class UsersListSerializer(serializers.ModelSerializer):
    class Meta:
        model = user_models.Users
        fields = ('id', 'email',)


class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = user_models.Users
        fields = ('id', 'full_name', 'username', 'email', 'image', 'phone_number',)


class UserDetailUpdateSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(min_length=2, max_length=68, allow_blank=True, required=False)
    phone_number = PhoneNumberField()
    image = serializers.ImageField(allow_null=True, required=False)

    class Meta:
        model = user_models.Users
        fields = ('full_name', 'phone_number', 'image')


class AuthorizationTokenSerializer(serializers.Serializer):  # noqa

    account = serializers.HyperlinkedRelatedField(
        queryset=user_models.Users.objects.all(),
        required=True,
        view_name='api:account-detail',
    )

    class Meta:
        fields = ['account']


class RegisterSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(max_length=68, min_length=6, write_only=True, required=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True, required=True)

    class Meta:
        model = user_models.Users
        fields = ("email", "password1", "password2")

    def validate(self, attrs):
        password1 = attrs.get('password1', '')
        password2 = attrs.get('password2', '')
        if password2 != password1:
            raise serializers.ValidationError("Passwords not equal")
        return attrs

    def create(self, validated_data):
        return user_models.Users.objects.create_user(email=validated_data['email'],
                                                     password=validated_data['password1'])


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = user_models.Users
        fields = 'token'


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=4)
    password = serializers.CharField(max_length=68, min_length=3, write_only=True)
    tokens = serializers.CharField(max_length=68, min_length=6, read_only=True)

    @staticmethod
    def get_tokens(obj):
        user = user_models.Users.objects.get(email=obj['email'])

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model = user_models.Users
        fields = ('email', 'password', 'tokens')

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again!')

        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')

        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'tokens': user.tokens
        }


class ResetPasswordEmailRequestSerializer(serializers.Serializer):  # noqa
    email = serializers.EmailField(min_length=3, max_length=68)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        model = user_models.Users
        fields = ['password1', 'password2', 'token', 'uidb64']

    def validate(self, attrs):
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        token = attrs.get('token')
        uidb64 = attrs.get('uidb64')

        pk = force_str(urlsafe_base64_decode(uidb64))
        user = user_models.Users.objects.get(id=pk)

        if password2 != password1:
            raise AuthenticationFailed("Passwords not equal")

        if not users_utils.PasswordResetTokenGenerator().check_token(user, token):
            raise AuthenticationFailed('The reset link link is invalid', 401)

        user.set_password(password1)
        user.save()

        return super().validate(attrs)


class LogoutSerializer(serializers.Serializer):  # noqa
    refresh = serializers.CharField()
    token = None

    default_error_message = {
        'bad_token': 'Token is expired or invalid'
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')
