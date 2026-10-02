from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("accounts.urls")),
    path("api/billing/", include("accounts.billing.urls")),
    path("api/dashboard/", include("accounts.dashboard.urls")),
    path("", include("accounts.sso.urls")),
    path("", include("accounts.audit.urls")),
    path("", include("accounts.siem.urls")),
    path("", include("accounts.compliance.urls")),
    path("", include("scanner.urls")),
]
