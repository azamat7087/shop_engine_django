from django.contrib import admin
from .models import *
from django.contrib.auth.admin import UserAdmin
# Register your models here.


class UsersAdmin(UserAdmin):
    list_display = ('email', 'full_name', 'username', 'date_joined', 'last_login', )
    search_fields = ('email', 'full_name', 'username',)
    readonly_fields = ('id', )
    ordering = ('id',)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )


admin.site.register(Users, UsersAdmin)
