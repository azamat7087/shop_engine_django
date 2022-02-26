import re
import inspect
from six import text_type

from django.conf import settings
from django.urls import reverse
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

import users.models as users_models


class AppTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return text_type(user.is_active) + text_type(user.id) + text_type(timestamp)


token_generator = AppTokenGenerator()


def delete_atomic_object(obj):
    if hasattr(obj, "delete"):
        getattr(obj, "delete")()


def get_header(request):
    regex = re.compile('^HTTP_')
    head = dict((regex.sub('', header), value) for (header, value)
                in request.META.items() if header.startswith('HTTP_'))
    return head


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')


def email_verification(request, user, email):
    uidb64 = urlsafe_base64_encode(force_bytes(user.id))
    token = token_generator.make_token(user)
    domain = get_current_site(request).domain
    link = reverse('activate_url', kwargs={'uidb64': uidb64, 'token': token})
    activate_url = 'https://' + domain + link
    send_mail(
        'Confirm your account',
        'Please confirm your account. Use this link to verify your account\n' + activate_url,
        f'{settings.EMAIL_HOST_USER}',
        [email],
        fail_silently=False,
    )


def get_user_data(request, email):
    user = users_models.Users.objects.get(email=email)
    ip = get_client_ip(request)
    os = str(request.user_agent.os.family) + " " + str(request.user_agent.os.version_string)
    browser = str(request.user_agent.browser.family)

    return user, ip, os, browser


class ViewSerializerMixin(generics.GenericAPIView):
    list_serializer_class = None

    @staticmethod
    def get_caller_name():
        current_frame = inspect.currentframe()
        call_frame = inspect.getouterframes(current_frame, 2)
        return call_frame[2][3]

    def get_serializer(self, *args, **kwargs):
        caller = self.get_caller_name()
        serializer_class = self.get_serializer_class()

        if caller == 'list':
            serializer_class = self.list_serializer_class
        elif caller == 'retrieve':
            serializer_class = self.serializer_class

        kwargs.setdefault('context', self.get_serializer_context())
        return serializer_class(*args, **kwargs)


class ListObjectsMixin(generics.ListAPIView):
    queryset = None
    serializer_class = None
    filter_backends = (DjangoFilterBackend,)
    permission_classes = []
    admin_only = False
    model = None
    user_private = None
    filter_fields = []
    search_fields = []

    def list(self, request, *args, **kwargs):
        if self.admin_only:
            user = users_models.Users.objects.get(id=request.user.id)
            if not user.is_staff:
                return Response({'success': False, "error": f"Forbidden"}, status.HTTP_403_FORBIDDEN)

        try:

            class_name = users_models.str_to_class(self.model)

            objects = class_name.objects.all()

            objects = self.filter_queryset(objects)

            page = self.paginate_queryset(objects)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            serializer = self.get_serializer(objects, many=True)

            return Response(serializer.data, status.HTTP_200_OK)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class RetrieveObjectsMixin(generics.RetrieveAPIView):
    serializer_class = None
    filter_backends = (DjangoFilterBackend,)
    permission_classes = []
    admin_only = False
    obj = None
    model = None
    user_private = None
    lookup_field = 'id'

    def retrieve(self, request, *args, **kwargs):
        if self.admin_only:
            user = users_models.Users.objects.get(id=request.user.id)
            if not user.is_staff:
                return Response({'success': False, "error": f"Forbidden"}, status.HTTP_403_FORBIDDEN)

        class_name = users_models.str_to_class(self.model)
        try:
            obj = class_name.objects.get(id=kwargs['id'])
            serializer = self.serializer_class(obj)
            return Response(serializer.data, status.HTTP_200_OK)
        except class_name.DoesNotExist:
            return Response(f'DoesNotExist. {self.obj} does not exist in {self.model}', status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'success': False, "error": f"{e}"},  status.HTTP_400_BAD_REQUEST)


class ViewMixin(ListObjectsMixin, RetrieveObjectsMixin, GenericViewSet):
    pass
