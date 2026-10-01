from django.urls import path

from .views import check_url_api, health_check_api

urlpatterns = [
    path("api/health/", health_check_api, name="health_check_api"),
    path("api/check-url/", check_url_api, name="check_url_api"),
]
