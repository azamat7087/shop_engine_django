from django.urls import path
import users.views as users_views
from django.conf.urls.static import static
from django.conf import settings
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [

    path('api/register/', users_views.RegisterView.as_view(), name='api_register_view'),
    # Registration[email, password]

    path('api/email-verify/', users_views.VerifyEmail.as_view(), name='api_email_verify_view'),
    # Verification[token]

    path('api/login/', users_views.LoginView.as_view(), name='api_login__view'),
    # Login[email, password]

    path('api/logout/', users_views.LogoutView.as_view(), name='api_logout_view'),
    # Logout[refresh token, auth token]

    path('api/password-reset-email/', users_views.RequestPasswordResetEmailView.as_view(),
         name="api_request_reset_email_view"),
    # Reset password[email]

    path('api/password-reset-complete/', users_views.SetNewPasswordView.as_view(),
         name="api_password_reset_complete_view"),
    # Reset complete [password, token, uidb64]

    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh_view'),
    # Token refresh[refresh token]

    path('api/password-reset/<uidb64>/<token>/', users_views.PasswordTokenCheckView.as_view(),
         name="api_password_reset_view"),
    # Password reset check[uidb64, token] from email

    path('api/user/', users_views.UsersView.as_view({'patch': 'update', 'get': 'retrieve'}), name='user_update'),

    path('api/admin/users/', users_views.UsersAdminView.as_view({'get': 'list'}), name='users_admin'),
    path('api/admin/users/<str:id>/', users_views.UsersAdminView.as_view({'get': 'retrieve'}), name='user_admin'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
