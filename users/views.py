import jwt
import json

from django.urls import reverse
from django.conf import settings
from django.db import transaction
from django.contrib.sites.shortcuts import get_current_site
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import DjangoUnicodeDecodeError, smart_bytes, smart_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, permissions, status
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.parsers import FileUploadParser, JSONParser, MultiPartParser, FormParser

import users.utils as users_utils
import users.models as users_models
import users.serializers as users_serializers
import users.filters as users_filters


class UsersAdminView(users_utils.ViewSerializerMixin, users_utils.ViewMixin):
    queryset = users_models.Users.objects.all()
    serializer_class = users_serializers.UsersSerializer
    list_serializer_class = users_serializers.UsersListSerializer
    model = 'Users'
    obj = 'user'
    admin_only = True
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    permission_classes = [permissions.IsAuthenticated, ]
    parser_classes = (MultiPartParser, JSONParser, FormParser)
    lookup_field = "id"
    filter_class = users_filters.UsersFilterSet
    filter_fields = []
    search_fields = ['full_name', 'username', 'email', 'phone_number']
    ordering_fields = ['id', 'last_login', 'date_joined', 'last_update']


class UsersView(GenericViewSet):
    queryset = users_models.Users.objects.filter(is_admin=False, is_superuser=False, is_staff=False)
    serializer_class = users_serializers.UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated, ]
    parser_classes = (MultiPartParser, FileUploadParser, JSONParser, FormParser)

    def retrieve(self, request, *args, **kwargs):
        try:
            obj = users_models.Users.objects.get(id=request.user.id)
            serializer = self.serializer_class(obj)
            return Response(serializer.data, status.HTTP_200_OK)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        try:
            user = users_models.Users.objects.get(id=request.user.id)

            serializer = users_serializers.UserDetailUpdateSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            for attr, value in request.data.items():
                if hasattr(user, attr):
                    setattr(user, attr, value)

            user.save()
            serializer = self.serializer_class(user)

            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class RegisterView(generics.GenericAPIView):

    serializer_class = users_serializers.RegisterSerializer

    @transaction.atomic
    def post(self, request):
        user = None
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            token = RefreshToken.for_user(user).access_token

            current_site = get_current_site(request).domain
            link = reverse('api_email_verify_view')

            abs_url = 'https://' + str(current_site) + str(link) + "?token=" + str(token)
            email_body = 'Hi ' + user.email + '. Use the below to verify your email \n' + abs_url
            data = {'email_body': email_body,
                    'email_subject': 'Verify your email',
                    'to_email': user.email,
                    }

            users_utils.Util.send_email(data)
            return Response({'success': True, "message": "Please check your email to verify account"},
                            status=status.HTTP_201_CREATED)
        except Exception as e:
            users_utils.delete_atomic_object(user)
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class VerifyEmail(APIView):
    serializer_class = users_serializers.EmailVerificationSerializer

    @staticmethod
    def get(request):
        token = request.GET.get('token', None)
        try:
            if not token:
                return Response({'success': False, 'error': 'Insert token'}, status=status.HTTP_400_BAD_REQUEST)

            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')

            user = users_models.Users.objects.get(id=payload['user_id'])

            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({'success': True, 'email': 'Successfully activated'}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({'success': False, 'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'success': False, 'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = users_serializers.LoginSerializer

    @transaction.atomic
    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)

            serialized_data = serializer.data

            serialized_data['tokens'] = json.loads(serialized_data['tokens'].replace("\'", "\""))
            return Response(serialized_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetEmailView(generics.GenericAPIView):
    serializer_class = users_serializers.ResetPasswordEmailRequestSerializer

    @staticmethod
    def get_email_data(request, user):
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        current_site = get_current_site(request=request).domain
        link = reverse('api_password_reset_view', kwargs={'uidb64': uidb64, 'token': token})

        return link, current_site

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)

            email = serializer.data.get('email', None)

            if not email:
                return Response({"error": "Insert email"}, status=status.HTTP_400_BAD_REQUEST)

            if users_models.Users.objects.filter(email=email).exists():
                user = users_models.Users.objects.get(email=email)

                link, current_site = self.get_email_data(request, user)

                abs_url = 'https://' + str(current_site) + str(link)
                email_body = 'Hello, \n Use link bellow to reset your password \n' + abs_url
                data = {'email_body': email_body,
                        'email_subject': 'Reset password',
                        'to_email': user.email,
                        }

                users_utils.Util.send_email(data)
                return Response({'success': True, 'message': 'We have sent you a link to reset your password'},
                                status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class PasswordTokenCheckView(APIView):
    serializer_class = None
    queryset = None

    @staticmethod
    def get(request, uidb64, token):
        try:
            pk = smart_str(urlsafe_base64_decode(uidb64))
            user = users_models.Users.objects.get(id=pk)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'success': False, 'error': 'Token is not valid, please request a new one'},
                                status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'message': 'Credentials valid', 'uidb64': uidb64, 'token': token},
                            status.HTTP_200_OK)

        except DjangoUnicodeDecodeError:
            return Response({'success': False, 'error': 'Token is not valid, please request a new one'},
                            status.HTTP_401_UNAUTHORIZED)
        except users_models.Users.DoesNotExist:
            return Response({'success': False, 'error': 'User is does not exist'}, status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = users_serializers.SetNewPasswordSerializer

    def patch(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)

            return Response({'success': True, 'messages': 'Password reset success'}, status.HTTP_200_OK)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class LogoutView(generics.GenericAPIView):
    serializer_class = users_serializers.LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response({'success': True, 'message': 'You logout successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)
