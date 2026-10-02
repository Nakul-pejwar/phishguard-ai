from django.urls import path

from .views import audit_logs_api

urlpatterns = [
    path("api/audit/logs/", audit_logs_api, name="audit_logs_api"),
]
