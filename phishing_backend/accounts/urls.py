from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    APIKeyListCreateView,
    APIKeyRevokeView,
    LoginView,
    MeView,
    RegisterView,
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="auth_register"),
    path("login/", LoginView.as_view(), name="auth_login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("me/", MeView.as_view(), name="auth_me"),
    path("api-keys/", APIKeyListCreateView.as_view(), name="api_keys_list_create"),
    path("api-keys/<int:pk>/revoke/", APIKeyRevokeView.as_view(), name="api_keys_revoke"),
]
