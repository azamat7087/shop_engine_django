from django_filters import CharFilter, BooleanFilter
from django_filters.rest_framework import FilterSet


class UsersFilterSet(FilterSet):
    is_admin = CharFilter(field_name="is_admin")
    is_verified = CharFilter(field_name="is_verified")
    is_staff = CharFilter(field_name="is_staff")
